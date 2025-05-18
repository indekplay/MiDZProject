from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
import requests
from django.contrib import messages
from .forms import UploadFileForm
from .models import IPAddress
from django.conf import settings
from django.db.models import Count
import io
from collections import defaultdict
from datetime import datetime, timedelta
API_KEY = settings.ABUSEIPDB_API_KEY
@login_required
def home(request):
    return render(request, 'home.html')

@login_required
def ip_list(request):
    ips = IPAddress.objects.all().order_by('-abuse_confidence_score')
    return render(request, 'ip_list.html', {'ips': ips})

@login_required
def chart(request):
    country_data = (
        IPAddress.objects
        .values('country_code')
        .annotate(count=Count('id'))
        .order_by('-count')
    )

    labels = [entry['country_code'] or 'Nieznany' for entry in country_data]
    counts = [entry['count'] for entry in country_data]

    return render(request, 'chart.html', {
        'labels': labels,
        'counts': counts,
    })

@login_required
def botnet(request):
    ip_records = IPAddress.objects.all()
    groups = defaultdict(list)
    for ip in ip_records:
        if not ip.usage_type or not ip.isp or not ip.last_reported_at:
            continue
        usage = ip.usage_type.strip()
        isp = ip.isp.strip()
        reported_date = ip.last_reported_at.date()
        matched_key = None
        for key in groups:
            if key[0] == usage and key[1] == isp:
                existing_date = key[2]
                if abs((reported_date - existing_date).days) <= 1:
                    matched_key = key
                    break
        if matched_key:
            groups[matched_key].append(ip)
        else:
            groups[(usage, isp, reported_date)].append(ip)
    grouped_botnets = [
        {
            'usage': key[0],
            'isp': key[1],
            'report_date': key[2],
            'ips': value,
            'ip_count': len(value)
        }
        for key, value in groups.items()
        if len(value) >= 3
    ]
    grouped_botnets.sort(key=lambda g: g['ip_count'], reverse=True)
    return render(request, 'botnet.html', {'botnets': grouped_botnets})

def handle_uploaded_file(f):
    content = f.read().decode('utf-8')
    ip_list = content.splitlines()
    return [ip.strip() for ip in ip_list if ip.strip()]

@login_required
def upload_file(request):
    if request.method == 'POST':
        form = UploadFileForm(request.POST, request.FILES)
        if form.is_valid():
            ip_addresses = handle_uploaded_file(request.FILES['ip_file'])
            total = len(ip_addresses)
            processed = 0
            errors = 0

            for ip in ip_addresses:
                try:
                    response = requests.get(
                        'https://api.abuseipdb.com/api/v2/check',
                        params={'ipAddress': ip, 'maxAgeInDays': 90},
                        headers={
                            'Key': API_KEY,
                            'Accept': 'application/json'
                        }
                    )
                    data = response.json().get('data', {})
                    score = data['abuseConfidenceScore']
                    if score > 0:
                        obj, created = IPAddress.objects.get_or_create(
                            ip_address=ip,
                            defaults={
                                'is_malicious': True,
                                'abuse_confidence_score': score,
                                'country_code': data.get('countryCode'),
                                'isp': data.get('isp'),
                                'domain': data.get('domain'),
                                'hostnames': ', '.join(data.get('hostnames', [])),
                                'usage_type': data.get('usageType'),
                                'total_reports': data.get('totalReports'),
                                'distinct_users': data.get('numDistinctUsers'),
                                'last_reported_at': data.get('lastReportedAt')
                            }
                        )
                        if created:
                            processed += 1
                    else:
                        continue
                except Exception as e:
                    errors += 1
                    messages.warning(request, f'Błąd przy IP {ip}: {str(e)}')

            messages.success(request, f'Przetworzono {processed} z {total} adresów IP. Błędy: {errors}')
            return redirect('upload')  # zostajesz na stronie upload
    else:
        form = UploadFileForm()
    return render(request, 'upload.html', {'form': form})