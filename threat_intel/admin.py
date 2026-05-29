from django.contrib import admin
from .models import Vulnerability

@admin.register(Vulnerability)
class VulnerabilityAdmin(admin.ModelAdmin):
    # columns to show up based on the extracted data
    list_display = ('cve_id', 'severity', 'base_score', 'published_date')
    
    search_fields = ('cve_id', 'description')
    
    list_filter = ('severity',)
    
    ordering = ('-published_date',)
