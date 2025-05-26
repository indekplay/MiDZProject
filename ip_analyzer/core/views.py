from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
import requests
from django.contrib import messages
from .forms import UploadFileForm
from .models import IPAddress
from django.db.models import Count
from collections import defaultdict

@login_required
def home(request):
    return render(request, 'home.html')


@login_required
def ip_list(request):
    attack_label = request.GET.get('attack', None)

    if attack_label:
        ips = IPAddress.objects.filter(attack_label=attack_label).order_by('-created_at')
    else:
        ips = IPAddress.objects.all().order_by('-created_at')

    attack_labels = (
        IPAddress.objects
        .exclude(attack_label__isnull=True)
        .exclude(attack_label__exact='')
        .values_list('attack_label', flat=True)
        .distinct()
        .order_by('attack_label')
    )

    return render(request, 'ip_list.html', {
        'ips': ips,
        'attack_labels': attack_labels,
        'selected_attack': attack_label,
    })



@login_required
def chart(request):
    selected_attack = request.GET.get('attack')

    if selected_attack:
        filtered_ips = IPAddress.objects.filter(attack_label=selected_attack)
    else:
        filtered_ips = IPAddress.objects.all()

    country_data = (
        filtered_ips
        .values('country_code')
        .annotate(count=Count('id'))
        .order_by('-count')
    )

    attack_labels = IPAddress.objects.values_list('attack_label', flat=True).distinct()

    labels = [entry['country_code'] or 'Nieznany' for entry in country_data]
    counts = [entry['count'] for entry in country_data]

    return render(request, 'chart.html', {
        'labels': labels,
        'counts': counts,
        'attack_labels': attack_labels,
        'selected_attack': selected_attack,
    })


@login_required
def botnet(request):
    selected_attack = request.GET.get('attack', None)

    if selected_attack:
        ip_records = IPAddress.objects.filter(attack_label=selected_attack)
    else:
        ip_records = IPAddress.objects.all()

    attack_labels = (
        IPAddress.objects
        .exclude(attack_label__isnull=True)
        .exclude(attack_label__exact='')
        .values_list('attack_label', flat=True)
        .distinct()
        .order_by('attack_label')
    )

    groups = defaultdict(list)
    for ip in ip_records:
        key = (ip.asn, ip.country_code)
        groups[key].append(ip)

    grouped = []
    for (asn, country), ips in groups.items():
        if len(ips) >= 10:
            grouped.append({
                'asn': asn or '–',
                'country': country or 'Nieznany',
                'count': len(ips),
                'ips': ips,
            })

    grouped.sort(key=lambda g: g['count'], reverse=True)

    return render(request, 'botnet.html', {
        'botnets': grouped,
        'attack_labels': attack_labels,
        'selected_attack': selected_attack,
    })


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
            attack_label = form.cleaned_data['attack_label']
            total = len(ip_addresses)
            processed = 0
            errors = 0
            IPINFO_TOKEN = '5294d8ba5efbff'

            for ip in ip_addresses:
                try:
                    response = requests.get(f"https://api.ipinfo.io/lite/{ip}?token={IPINFO_TOKEN}")
                    if response.status_code != 200:
                        raise Exception(f"Błąd API: {response.status_code}")
                    data = response.json()

                    IPAddress.objects.get_or_create(
                        ip_address=ip,
                        defaults={
                            'asn': data.get('asn'),
                            'as_name': data.get('as_name'),
                            'as_domain': data.get('as_domain'),
                            'country_code': data.get('country_code'),
                            'country': data.get('country'),
                            'continent_code': data.get('continent_code'),
                            'continent': data.get('continent'),
                            'attack_label': attack_label,
                        }
                    )
                    processed += 1
                except Exception as e:
                    errors += 1
                    messages.warning(request, f'Błąd przy IP {ip}: {str(e)}')

            messages.success(request, f'Przetworzono {processed} z {total} adresów IP. Błędy: {errors}')
            return redirect('upload')
    else:
        form = UploadFileForm()

    return render(request, 'upload.html', {'form': form})
