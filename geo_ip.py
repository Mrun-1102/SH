import ipaddress
import os

try:
	import maxminddb
except Exception:
	maxminddb = None


MODULE_DIR = os.path.dirname(__file__)
CITY_MMDB_PATH = os.path.join(MODULE_DIR, 'geolite2-city-ipv4.mmdb')
ASN_MMDB_PATH = os.path.join(MODULE_DIR, 'geolite2-asn-ipv4.mmdb')
_reader_cache = {}


def _resolve_mmdb_path(default_path, explicit_path=None):
	if explicit_path:
		return explicit_path if os.path.exists(explicit_path) else None

	return default_path if os.path.exists(default_path) else None


def _safe_get(data, *path):
	current = data
	for key in path:
		if not isinstance(current, dict):
			return None
		current = current.get(key)
		if current is None:
			return None
	return current


_COUNTRY_MAP = {
    "US": "United States", "GB": "United Kingdom", "CN": "China", "RU": "Russia",
    "DE": "Germany", "FR": "France", "JP": "Japan", "IN": "India", "BR": "Brazil",
    "CA": "Canada", "AU": "Australia", "KR": "South Korea", "NL": "Netherlands",
    "SG": "Singapore", "HK": "Hong Kong", "TW": "Taiwan"
}

def _normalize_country(record):
    code = record.get('country_code') or _safe_get(record, 'country', 'iso_code')
    full_name = (
        _safe_get(record, 'country', 'names', 'en')
        or _safe_get(record, 'country', 'name')
        or _safe_get(record, 'registered_country', 'names', 'en')
        or _safe_get(record, 'registered_country', 'name')
        or record.get('country_name')
    )
    
    if not full_name and code:
        full_name = _COUNTRY_MAP.get(code.upper(), code)
        
    return full_name or code


def _normalize_isp(record):
	return (
		record.get('isp')
		or record.get('organization')
		or record.get('org')
		or _safe_get(record, 'traits', 'isp')
		or _safe_get(record, 'traits', 'organization')
		or _safe_get(record, 'autonomous_system_organization')
		or _safe_get(record, 'asn', 'organization')
	)


def _normalize_city(record):
	return (
		_safe_get(record, 'city', 'names', 'en')
		or _safe_get(record, 'city', 'name')
		or record.get('city')
	)


def _normalize_lat_lon(record):
	latitude = _safe_get(record, 'location', 'latitude')
	longitude = _safe_get(record, 'location', 'longitude')

	if latitude is None:
		latitude = record.get('latitude')
	if longitude is None:
		longitude = record.get('longitude')

	try:
		if latitude is not None and longitude is not None:
			lat = float(latitude)
			lon = float(longitude)
			# Treat null-island placeholders as missing geolocation.
			if lat == 0.0 and lon == 0.0:
				return None, None
			return lat, lon
	except (TypeError, ValueError):
		return None, None

	return None, None


def _get_reader(default_path, mmdb_path=None):
	path = _resolve_mmdb_path(default_path, mmdb_path)
	if not path or maxminddb is None:
		return None

	if path in _reader_cache:
		return _reader_cache[path]

	try:
		reader = maxminddb.open_database(path)
		_reader_cache[path] = reader
		return reader
	except Exception:
		return None


def lookup_ip_geolocation(ip, mmdb_path=None, asn_mmdb_path=None):
	try:
		ip_obj = ipaddress.ip_address(str(ip))
		if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_multicast:
			return {}
	except Exception:
		return {}

	city_reader = _get_reader(CITY_MMDB_PATH, mmdb_path)
	asn_reader = _get_reader(ASN_MMDB_PATH, asn_mmdb_path)

	if city_reader is None and asn_reader is None:
		return {}

	try:
		city_record = city_reader.get(str(ip)) if city_reader is not None else {}
		asn_record = asn_reader.get(str(ip)) if asn_reader is not None else {}
	except Exception:
		return {}

	city_record = city_record if isinstance(city_record, dict) else {}
	asn_record = asn_record if isinstance(asn_record, dict) else {}

	if not city_record and not asn_record:
		return {}

	country = _normalize_country(city_record) or _normalize_country(asn_record)
	isp = _normalize_isp(asn_record) or _normalize_isp(city_record)
	city = _normalize_city(city_record) or _normalize_city(asn_record)
	latitude, longitude = _normalize_lat_lon(city_record)
	if latitude is None or longitude is None:
		latitude, longitude = _normalize_lat_lon(asn_record)

	asn = _safe_get(asn_record, 'autonomous_system_number') or _safe_get(city_record, 'autonomous_system_number')

	return {
		'country': country,
		'isp': isp,
		'city': city,
		'latitude': latitude,
		'longitude': longitude,
		'asn': f"AS{asn}" if asn else None
	}


def enrich_external_ips_with_geo(external_ips, mmdb_path=None, asn_mmdb_path=None):
	enriched = []
	for item in external_ips or []:
		row = dict(item)
		ip = row.get('ip')
		if not ip:
			enriched.append(row)
			continue

		geo = lookup_ip_geolocation(ip, mmdb_path=mmdb_path, asn_mmdb_path=asn_mmdb_path)
		row['country'] = geo.get('country') or row.get('country')
		row['isp'] = geo.get('isp') or row.get('isp')
		row['city'] = geo.get('city')
		row['latitude'] = geo.get('latitude')
		row['longitude'] = geo.get('longitude')
		enriched.append(row)

	return enriched
