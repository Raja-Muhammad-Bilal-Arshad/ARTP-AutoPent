DEFAULT_OBJECTIVES = [
    {"id":"discover_endpoints", "desc":"Discover HTTP endpoints and interesting paths", "priority":100},
    {"id":"find_admin", "desc":"Locate administrative pages (/admin, /manage)", "priority":90},
    {"id":"check_auth", "desc":"Look for login pages and test default creds (simulated)", "priority":80},
    {"id":"identify_services", "desc":"Enumerate services such as LDAP, MSRPC", "priority":70},
    {"id":"attempt_low_impact", "desc":"Attempt low-impact simulated exploits where safe", "priority":50}
]
