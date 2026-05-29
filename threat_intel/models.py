from django.db import models

# Create your models here.

class Vulnerability(models.Model):
    cve_id = models.CharField(max_length=20, unique=True, db_index=True)
    description = models.TextField()
    base_score = models.FloatField(null=True, blank=True)
    severity = models.CharField(max_length=20, null=True, blank=True)
    published_date = models.DateTimeField()
    last_modified_date = models.DateTimeField()

    def __str__(self):
        return f"{self.cve_id} - {self.severity}"
