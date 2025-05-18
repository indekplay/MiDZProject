from django.db import models

class IPAddress(models.Model):
    ip_address = models.GenericIPAddressField(unique=True)
    is_malicious = models.BooleanField()
    abuse_confidence_score = models.IntegerField()
    country_code = models.CharField(max_length=5, null=True, blank=True)
    isp = models.CharField(max_length=255, null=True, blank=True)
    domain = models.CharField(max_length=255, null=True, blank=True)
    hostnames = models.TextField(null=True, blank=True)
    usage_type = models.CharField(max_length=255, null=True, blank=True)
    total_reports = models.IntegerField(null=True, blank=True)
    distinct_users = models.IntegerField(null=True, blank=True)
    last_reported_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.ip_address