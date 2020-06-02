port = 8834
ssl_verify = False

url = "nessus.astelit.ukr"
accessKey = "078f7f2eb095ed7cd9beb63e58704b256d94298e68d00ffc07cce4e51351e233"
secretKey = "73f33c1220fbe9d16b35920676134b417c46dbb346a9003aff0458f05dff74a0"

plugin_slots = ("name", "family_name", "id", "asset_categories", "hardware_inventory", "exploitability_ease",
                "canvas_package", "cvss_score_source", "mskb", "ssa", "icsa", "clsa", "malware", "cvss3_vector",
                "unsupported_by_vendor", "iavb", "cisco-sa", "exploithub_sku", "owasp", "exploit_available", "tra",
                "tslsa", "cvss3_base_score", "certa", "required_port", "cisco-bug-id", "ics-alert", "always_run",
                "hpsb", "exploit_framework_canvas", "cvss_vector", "cvss_score_rationale", "cvss3_temporal_vector",
                "glsa", "zdi", "plugin_publication_date", "cert", "nsfocus", "patch_modification_date",
                "generated_plugin", "exploited_by_malware", "cvss_base_score", "secunia", "asset_inventory",
                "msft", "plugin_modification_date", "dependency", "freebsd", "script_version", "vmsa", "tlsa",
                "iavt", "bid", "flsa", "cert-fi", "iava", "mdvsa", "patch_publication_date", "required_key",
                "mdksa", "hp", "d2_elliot_name", "cvss_temporal_vector", "exploit_framework_d2_elliot", "cwe",
                "stig_severity", "plugin_name", "cvss_temporal_score", "vuln_publication_date", "risk_factor",
                "compliance", "see_also", "metasploit_name", "exploit_framework_core", "default_account",
                "excluded_key", "auscert", "fname", "edb-id", "os_identification", "script_copyright", "apple-sa",
                "exploit_framework_metasploit", "cve", "solution", "exploit_framework_exploithub",
                "exploited_by_nessus", "rhsa", "in_the_news", "dsa", "cvss3_temporal_score", "xref",
                "potential_vulnerability", "cisco-sr", "cert-cc", "suse", "fedora", "agent", "usn", "synopsis",
                "cpe", "openpkg-sa", "required_udp_port", "plugin_type", "description")

scan_slots = ("connector", "id", "owner", "container_id", "uuid", "name", "description", "policy_id",
              "scanner_id", "emails", "attach_report", "attached_report_maximum_size", "attached_report_type",
              "sms", "enabled", "use_dashboard", "dashboard_file", "live_results", "scan_time_window",
              "custom_targets", "migrated", "starttime", "rrules", "timezone", "notification_filters", "tag_id",
              "shared", "user_permissions", "default_permisssions", "owner_id", "last_modification_date",
              "creation_date", "type", "_details")
