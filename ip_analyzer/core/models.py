from django.db import models



class IPAddress(models.Model):
    ip_address = models.GenericIPAddressField()
    asn = models.CharField(max_length=20, blank=True, null=True)
    as_name = models.CharField(max_length=255, blank=True, null=True)
    as_domain = models.CharField(max_length=255, blank=True, null=True)
    country_code = models.CharField(max_length=10, blank=True, null=True)
    country = models.CharField(max_length=100, blank=True, null=True)
    continent_code = models.CharField(max_length=10, blank=True, null=True)
    continent = models.CharField(max_length=100, blank=True, null=True)

    attack_label = models.CharField(max_length=100, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('ip_address', 'attack_label')

    def __str__(self):
        return self.ip_address
