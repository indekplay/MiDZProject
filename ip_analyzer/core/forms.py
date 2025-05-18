from django import forms

class UploadFileForm(forms.Form):
    ip_file = forms.FileField(label='Wgraj plik .txt z adresami IP')