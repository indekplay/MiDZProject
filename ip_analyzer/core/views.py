from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
import requests
from django.contrib import messages
from .forms import UploadFileForm
from .models import IPAddress
from django.db.models import Count,Min
from collections import defaultdict
from django import forms
from django.core.paginator import Paginator
from django.http import HttpResponse

class AttackComparisonForm(forms.Form):
    attack_1 = forms.ChoiceField(label="Atak 1")
    attack_2 = forms.ChoiceField(label="Atak 2")

    def __init__(self, *args, **kwargs):
        attack_choices = kwargs.pop('attack_choices', [])
        super().__init__(*args, **kwargs)
        self.fields['attack_1'].choices = attack_choices
        self.fields['attack_2'].choices = attack_choices

@login_required
def home(request):
    return render(request, 'home.html')


@login_required
def ip_list(request):
    selected_attack = request.GET.get('attack')
    if selected_attack:
        queryset = IPAddress.objects.filter(attack_label=selected_attack)
    else:
        queryset = IPAddress.objects.all()

    paginator = Paginator(queryset, 50)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    current_page = page_obj.number
    total_pages = paginator.num_pages
    start_page = max(current_page - 2, 1)
    end_page = min(current_page + 2, total_pages)
    page_range = range(start_page, end_page + 1)

    attack_labels = IPAddress.objects.values_list('attack_label', flat=True).distinct()

    return render(request, 'ip_list.html', {
        'ips': page_obj,
        'attack_labels': attack_labels,
        'selected_attack': selected_attack,
        'page_range': page_range,
        'total_pages': total_pages,
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
    prefix_length = request.GET.get('prefix_length', '1')
    try:
        prefix_length = int(prefix_length)
    except ValueError:
        prefix_length = 1

    try:
        prefix_length = int(prefix_length)
        if prefix_length < 1 or prefix_length > 4:
            prefix_length = 2
    except ValueError:
        prefix_length = 2

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

    def get_ip_prefix(ip, length):
        parts = ip.split('.')
        if len(parts) == 4 and 1 <= length <= 4:
            prefix_parts = parts[:length]
            suffix_parts = ['x'] * (4 - length)
            return '.'.join(prefix_parts + suffix_parts)
        return ip

    groups = defaultdict(list)
    for ip in ip_records:
        ip_prefix = get_ip_prefix(ip.ip_address, prefix_length)
        key = (ip.asn, ip.country_code, ip_prefix)
        groups[key].append(ip)

    grouped = []
    for (asn, country, ip_prefix), ips in groups.items():
        if len(ips) >= 10:
            grouped.append({
                'asn': asn or '–',
                'country': country or 'Nieznany',
                'ip_prefix': ip_prefix,
                'count': len(ips),
                'ips': ips,
            })

    grouped.sort(key=lambda g: g['count'], reverse=True)

    prefix_lengths = [1, 2, 3]

    return render(request, 'botnet.html', {
        'botnets': grouped,
        'attack_labels': attack_labels,
        'selected_attack': selected_attack,
        'prefix_length': prefix_length,
        'prefix_lengths': prefix_lengths,
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

                    exists = IPAddress.objects.filter(ip_address=ip, attack_label=attack_label).exists()
                    if not exists:
                        IPAddress.objects.create(
                            ip_address=ip,
                            asn=data.get('asn'),
                            as_name=data.get('as_name'),
                            as_domain=data.get('as_domain'),
                            country_code=data.get('country_code'),
                            country=data.get('country'),
                            continent_code=data.get('continent_code'),
                            continent=data.get('continent'),
                            attack_label=attack_label,
                        )
                        processed += 1
                    else:
                        pass

                except Exception as e:
                    errors += 1
                    messages.warning(request, f'Błąd przy IP {ip}: {str(e)}')

            messages.success(request, f'Przetworzono {processed} z {total} adresów IP. Błędy: {errors}')
            return redirect('upload')
    else:
        form = UploadFileForm()

    return render(request, 'upload.html', {'form': form})


@login_required
def analiza(request):
    attack_labels = IPAddress.objects \
        .exclude(attack_label__isnull=True) \
        .exclude(attack_label__exact='') \
        .values_list('attack_label', flat=True).distinct().order_by('attack_label')

    attack_choices = [(label, label) for label in attack_labels]

    if request.method == 'POST':
        form = AttackComparisonForm(request.POST, attack_choices=attack_choices)
        if form.is_valid():
            attack1 = form.cleaned_data['attack_1']
            attack2 = form.cleaned_data['attack_2']

            ips1 = set(IPAddress.objects.filter(attack_label=attack1).values_list('ip_address', flat=True))
            ips2 = set(IPAddress.objects.filter(attack_label=attack2).values_list('ip_address', flat=True))
            common_ips = ips1 & ips2

            if 'export' in request.POST:
                response = HttpResponse(content_type='text/plain')
                response['Content-Disposition'] = 'attachment; filename="wspolne_ip.txt"'
                response.write('\n'.join(sorted(common_ips)))
                return response

            ip_records = (
                IPAddress.objects
                .filter(ip_address__in=common_ips)
                .values('ip_address')
                .annotate(id_min=Min('id'))
            )
            final_records = IPAddress.objects.filter(id__in=[r['id_min'] for r in ip_records]).order_by('ip_address')

            return render(request, 'analiza.html', {
                'form': form,
                'common_ips': final_records,
                'selected_attack_1': attack1,
                'selected_attack_2': attack2
            })
    else:
        form = AttackComparisonForm(attack_choices=attack_choices)

    return render(request, 'analiza.html', {'form': form})
