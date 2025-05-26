from django import forms

class UploadFileForm(forms.Form):
    ip_file = forms.FileField(label='Wgraj plik .txt z adresami IP')
    attack_label = forms.CharField(
        label='Nazwa ataku',
        max_length=255,
        required=True,
        widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'np. atak_DDoS_kwiecien'})
    )