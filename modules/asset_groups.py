import os
import logging
import requests
from requests.auth import HTTPBasicAuth
import csv
from datetime import datetime


def get_insightvm_credentials():
    """Get InsightVM credentials from environment variables."""
    insightvm_host = os.getenv('INSIGHTVM_HOST')
    username = os.getenv('USERNAME')
    password = os.getenv('PASSWORD')
    
    if not all([insightvm_host, username, password]):
        raise ValueError("Missing required environment variables: INSIGHTVM_HOST, USERNAME, PASSWORD")
    
    return insightvm_host, username, password


def fetch_asset_groups():
    """Fetch all asset groups from InsightVM."""
    try:
        insightvm_host, username, password = get_insightvm_credentials()
        
        print("🔄 Fetching asset groups from InsightVM...")
        logging.info("🔄 Fetching asset groups from InsightVM")
        
        # API endpoint for asset groups
        url = f"{insightvm_host}/api/3/asset_groups"
        
        response = requests.get(
            url,
            auth=HTTPBasicAuth(username, password),
            verify=False,  # Skip SSL verification if needed
            timeout=30
        )
        
        if response.status_code == 200:
            return response.json()
        else:
            raise requests.exceptions.HTTPError(f"HTTP {response.status_code}: {response.text}")
            
    except requests.exceptions.RequestException as e:
        logging.error(f"❌ Network error while fetching asset groups: {e}")
        raise
def _fetch_all_pages(relative_path, query_params=None, page_size=500, timeout_s=60, max_pages=None, retries=0):
    """Fetch all pages for a given API v3 collection endpoint and return merged resources.

    timeout_s: per-request timeout in seconds
    max_pages: optional hard cap on number of pages to fetch
    retries: number of simple retries per request when transient errors occur
    """
    try:
        insightvm_host, username, password = get_insightvm_credentials()
        resources = []
        page_index = 0
        while True:
            params = {**(query_params or {}), 'page': page_index, 'size': page_size}
            url = f"{insightvm_host}{relative_path}"
            is_software_endpoint = '/software' in relative_path
            attempt = 0
            last_exc = None
            while attempt <= retries:
                try:
                    response = requests.get(
                        url,
                        params=params,
                        auth=HTTPBasicAuth(username, password),
                        verify=False,
                        timeout=timeout_s
                    )
                    if response.status_code != 200:
                        raise requests.exceptions.HTTPError(f"HTTP {response.status_code}: {response.text}")
                    break
                except Exception as e:
                    last_exc = e
                    attempt += 1
                    if attempt > retries:
                        raise

            data = response.json() or {}
            page_resources = data.get('resources', [])
            resources.extend(page_resources)

            # Stop if this page returned fewer than page_size or no pagination info
            total_pages = None
            page_info = data.get('page') or {}
            if isinstance(page_info, dict):
                total_pages = page_info.get('totalPages')
                if is_software_endpoint:
                    total_count = page_info.get('totalElements')
                    print(f"    📄 Paginated fetch {relative_path}: page {page_index+1}/{total_pages} size={len(page_resources)} total={total_count}")
            if total_pages is not None and page_index + 1 >= total_pages:
                break
            if not page_resources or len(page_resources) < page_size:
                break

            page_index += 1
            if max_pages is not None and page_index >= max_pages:
                break

        return {'resources': resources}
    except Exception as e:
        logging.error(f"❌ Error during paginated fetch for {relative_path}: {e}")
        raise

    except Exception as e:
        logging.error(f"❌ Error fetching asset groups: {e}")
        raise


def display_asset_groups(asset_groups):
    """Display asset groups in a formatted table."""
    if 'resources' in asset_groups and asset_groups['resources']:
        print(f"\n📋 Found {len(asset_groups['resources'])} asset groups:")
        print("-" * 60)
        print(f"{'ID':<8} {'Name':<30} {'Description':<40}")
        print("-" * 60)
        
        for group in asset_groups['resources']:
            group_id = group.get('id', 'N/A')
            group_name = group.get('name', 'N/A')[:29]
            group_desc = group.get('description', 'N/A')[:39] if group.get('description') else 'N/A'
            print(f"{group_id:<8} {group_name:<30} {group_desc:<40}")
        
        print("-" * 60)
        print(f"💡 Use --get-software <asset_group_id> to get software for a specific group")
        
    else:
        print("ℹ️  No asset groups found.")


def show_asset_groups():
    """Main function to show all available asset groups."""
    try:
        asset_groups = fetch_asset_groups()
        display_asset_groups(asset_groups)
        
    except ValueError as e:
        print(f"❌ {e}")
    except requests.exceptions.HTTPError as e:
        print(f"❌ Failed to fetch asset groups: {e}")
    except Exception as e:
        print(f"❌ Error fetching asset groups: {e}")


def fetch_assets_in_group(asset_group_id):
    """Fetch all assets in a specific asset group."""
    try:
        # Use paginated fetch to avoid missing assets
        return _fetch_all_pages(f"/api/3/asset_groups/{asset_group_id}/assets", timeout_s=30, retries=1)
    except requests.exceptions.RequestException as e:
        logging.error(f"❌ Network error while fetching assets: {e}")
        raise
def get_installed_software_for_site(site_id=2):
    """Export installed software for all assets in a site, saving one CSV per page."""
    try:
        print(f"🔄 Fetching installed software for site ID: {site_id}")
        logging.info(f"🔄 Fetching installed software for site ID: {site_id}")

        page_index = 0
        page_size = 500
        total_pages = None
        total_assets_processed = 0
        total_pages_saved = 0

        while True:
            try:
                insightvm_host, username, password = get_insightvm_credentials()
                response = requests.get(
                    f"{insightvm_host}/api/3/sites/{site_id}/assets",
                    params={'page': page_index, 'size': page_size},
                    auth=HTTPBasicAuth(username, password),
                    verify=False,
                    timeout=60
                )
                if response.status_code != 200:
                    raise requests.exceptions.HTTPError(f"HTTP {response.status_code}: {response.text}")
                data = response.json() or {}
            except Exception as e:
                print(f"❌ Error fetching site assets page {page_index+1}: {e}")
                break

            assets = data.get('resources', [])
            page_info = data.get('page') or {}
            total_pages = page_info.get('totalPages', None)

            if not assets:
                if page_index == 0:
                    print(f"ℹ️  No assets found in site {site_id}")
                break

            print(f"\n📄 Processing site {site_id} - page {page_index+1}{'/' + str(total_pages) if total_pages else ''} with {len(assets)} assets")

            if isinstance(assets[0], int):
                detailed_assets = []
                for asset_id in assets:
                    try:
                        asset_details = fetch_asset_details(asset_id)
                        detailed_assets.append(asset_details)
                    except Exception as e:
                        print(f"  ⚠️  Could not fetch details for asset {asset_id}: {e}")
                        detailed_assets.append({'id': asset_id, 'ip': 'Unknown'})
                assets = detailed_assets

            page_software = {}
            page_asset_count = 0
            for asset in assets:
                try:
                    if process_asset_software(asset, page_software):
                        page_asset_count += 1
                except Exception as e:
                    aid = asset.get('id') if isinstance(asset, dict) else asset
                    print(f"  ⚠️  Skipping asset {aid} due to error: {e}")

            if page_software:
                display_software_summary(page_software, f"site_{site_id}_page_{page_index+1}", page_asset_count)
                save_software_to_csv(page_software, f"site_{site_id}_page_{page_index+1}")
                total_pages_saved += 1
                total_assets_processed += page_asset_count
            else:
                print(f"ℹ️  No software found on page {page_index+1}")

            page_index += 1
            if total_pages is not None and page_index >= total_pages:
                break

        print(f"\n✅ Completed site export. Pages saved: {total_pages_saved}, assets processed: {total_assets_processed}")
        return {}, total_assets_processed

    except Exception as e:
        print(f"❌ Error fetching site software: {e}")
        logging.error(f"❌ Error fetching site software: {e}")
        import traceback
        traceback.print_exc()
        return {}, 0

    except Exception as e:
        logging.error(f"❌ Error fetching assets: {e}")
        raise


def fetch_assets_in_site(site_id):
    """Fetch all assets in a specific site (paginated)."""
    try:
        # Use paginated fetch to include all assets in the site
        return _fetch_all_pages(f"/api/3/sites/{site_id}/assets", timeout_s=30, retries=1)
    except requests.exceptions.RequestException as e:
        logging.error(f"❌ Network error while fetching site assets: {e}")
        raise
    except Exception as e:
        logging.error(f"❌ Error fetching site assets: {e}")
        raise


def fetch_asset_details(asset_id):
    """Fetch full asset details including IP address."""
    try:
        insightvm_host, username, password = get_insightvm_credentials()
        
        asset_url = f"{insightvm_host}/api/3/assets/{asset_id}"
        
        response = requests.get(
            asset_url,
            auth=HTTPBasicAuth(username, password),
            verify=False,
            timeout=10
        )
        if response.status_code == 200:
            return response.json()
        else:
            raise requests.exceptions.HTTPError(f"HTTP {response.status_code}: {response.text}")
            
    except requests.exceptions.RequestException as e:
        logging.error(f"❌ Network error while fetching asset details: {e}")
        raise
    except Exception as e:
        logging.error(f"❌ Error fetching asset details: {e}")
        raise


def fetch_software_for_asset(asset_id):
    """Fetch software information for a specific asset."""
    try:
        print(f"    ↪️  Calling /api/3/assets/{asset_id}/software with pagination ...")
        # Use paginated fetch to capture full software list for the asset
        # Shorter timeout and a retry to avoid long hangs on slow assets
        software_page_size = int(os.getenv('SOFTWARE_PAGE_SIZE', '200'))
        software_max_pages = int(os.getenv('SOFTWARE_MAX_PAGES', '2'))
        result = _fetch_all_pages(
            f"/api/3/assets/{asset_id}/software",
            page_size=software_page_size,
            timeout_s=15,
            retries=1,
            max_pages=software_max_pages
        )
        size = len(result.get('resources', []) or [])
        print(f"    ↩️  Received {size} software items for asset_id={asset_id}")
        return result
    except requests.exceptions.RequestException as e:
        logging.error(f"❌ Network error while fetching software: {e}")
        raise
    except Exception as e:
        logging.error(f"❌ Error fetching software: {e}")
        raise


def process_asset_software(asset, all_software):
    """Process software information for a single asset."""
    asset_id = asset.get('id')
    
    # Handle case where we only have asset ID
    if asset_id is None:
        print(f"  ❌ Asset has no ID: {asset}")
        return False
    
    # Try to get asset name and IP, use defaults if not available
    asset_name = asset.get('hostName', f'Asset_{asset_id}')
    asset_ip = asset.get('ip', 'Unknown')
    
    print(f"\n🔄 Processing asset: {asset_name} ({asset_ip})")
    print(f"  🕘 Preparing to fetch software for asset_id={asset_id}")
    
    try:
        import time as _time
        _t0 = _time.time()
        print(f"  🌐 Requesting software list from API for asset_id={asset_id} ...")
        software_data = fetch_software_for_asset(asset_id)
        _elapsed = _time.time() - _t0
        print(f"  ✅ Software API returned in {round(_elapsed, 2)}s for asset_id={asset_id}")
        
        if 'resources' in software_data and software_data['resources']:
            for sw in software_data['resources']:
                # Try different possible field names for software information
                # InsightVM API v3 might use different field names
                sw_name = sw.get('name') or sw.get('product') or sw.get('softwareName') or sw.get('title') or 'Unknown'
                sw_version = sw.get('version') or sw.get('softwareVersion') or sw.get('release') or 'Unknown'
                sw_vendor = sw.get('vendor') or sw.get('softwareVendor') or sw.get('publisher') or sw.get('manufacturer') or 'Unknown'
                sw_family = sw.get('family') or sw.get('softwareFamily') or sw.get('category') or sw.get('type') or 'Unknown'
                
                # Create a unique key for the software
                sw_key = f"{sw_vendor}|{sw_family}|{sw_name}|{sw_version}"
                
                if sw_key not in all_software:
                    all_software[sw_key] = {
                        'vendor': sw_vendor,
                        'family': sw_family,
                        'name': sw_name,
                        'version': sw_version,
                        'assets': []
                    }
                
                all_software[sw_key]['assets'].append({
                    'id': asset_id,
                    'name': asset_name,
                    'ip': asset_ip
                })
            
            print(f"  ✅ Found {len(software_data['resources'])} software items")
            return True
            
        else:
            print(f"  ℹ️  No software found for asset_id={asset_id}")
            return True
            
    except Exception as e:
        print(f"  ❌ Error processing asset {asset_id}: {e}")
        import traceback as _tb
        _tb.print_exc()
        return False


def display_software_summary(all_software, asset_group_id, asset_count):
    """Display software summary in a formatted table."""
    if all_software:
        print(f"\n📋 Software Summary for Asset Group {asset_group_id}:")
        print("=" * 80)
        print(f"{'Vendor':<20} {'Family':<20} {'Software':<25} {'Version':<15}")
        print("=" * 80)
        
        # Sort software by vendor, family, name
        sorted_software = sorted(all_software.keys(), key=lambda x: all_software[x]['vendor'] + all_software[x]['family'] + all_software[x]['name'])
        
        for sw_key in sorted_software:
            sw_info = all_software[sw_key]
            vendor = sw_info['vendor'][:19]
            family = sw_info['family'][:19]
            name = sw_info['name'][:24]
            version = sw_info['version'][:14]
            
            print(f"{vendor:<20} {family:<20} {name:<25} {version:<15}")
        
        print("=" * 80)
        print(f"📊 Total unique software items: {len(all_software)}")
        print(f"📊 Total assets processed: {asset_count}")
        
    else:
        print(f"\nℹ️  No software found in asset group {asset_group_id}")



def save_software_to_csv(software_data, asset_group_id):
    """Save software data to a CSV file."""
    try:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"software_asset_group_{asset_group_id}_{timestamp}.csv"
        
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['Vendor', 'Family', 'Software Name', 'Version', 'Asset Count', 'Asset Details']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            writer.writeheader()
            
            for sw_key, sw_info in software_data.items():
                asset_details = "; ".join([asset['ip'] for asset in sw_info['assets']])
                
                writer.writerow({
                    'Vendor': sw_info['vendor'],
                    'Family': sw_info['family'],
                    'Software Name': sw_info['name'],
                    'Version': sw_info['version'],
                    'Asset Count': len(sw_info['assets']),
                    'Asset Details': asset_details
                })
        
        print(f"💾 Software data saved to: {filename}")
        logging.info(f"💾 Software data saved to: {filename}")
        
    except Exception as e:
        print(f"❌ Error saving to CSV: {e}")
        logging.error(f"❌ Error saving to CSV: {e}")


def get_installed_software(asset_group_id):
    """Main function to get all installed software for a specific asset group."""
    try:
        print(f"🔄 Fetching installed software for asset group ID: {asset_group_id}")
        logging.info(f"🔄 Fetching installed software for asset group ID: {asset_group_id}")
        
        # Get assets in the asset group
        assets_data = fetch_assets_in_group(asset_group_id)
        
        if 'resources' not in assets_data or not assets_data['resources']:
            print(f"ℹ️  No assets found in asset group {asset_group_id}")
            return
        
        assets = assets_data['resources']
        print(f"📊 Found {len(assets)} assets in asset group {asset_group_id}")
        
        # Debug: Check the structure of the first asset
        if assets:
            print(f"🔍 Debug: First asset structure: {type(assets[0])} - {assets[0]}")
            if isinstance(assets[0], int):
                print("⚠️  Warning: Assets are returned as integers, not dictionaries")
                print("🔄 Fetching full asset details for each asset ID...")
                # If assets are just IDs, fetch full asset details including IP addresses
                detailed_assets = []
                for asset_id in assets:
                    try:
                        asset_details = fetch_asset_details(asset_id)
                        detailed_assets.append(asset_details)
                        print(f"  🔍 Fetched details for asset {asset_id}: {asset_details.get('ip', 'No IP')}")
                    except Exception as e:
                        print(f"  ⚠️  Could not fetch details for asset {asset_id}: {e}")
                        # Fallback to basic asset object
                        detailed_assets.append({'id': asset_id, 'ip': 'Unknown'})
                assets = detailed_assets
        
        # Collect software information from all assets
        all_software = {}
        asset_count = 0
        
        for asset in assets:
            if process_asset_software(asset, all_software):
                asset_count += 1
        
        # Display summary
        display_software_summary(all_software, asset_group_id, asset_count)
        
        # Auto-save for single asset group
        if all_software:
            save_software_to_csv(all_software, asset_group_id)
        
        return all_software, asset_count
        
    except ValueError as e:
        print(f"❌ {e}")
        return {}, 0
    except requests.exceptions.HTTPError as e:
        print(f"❌ Failed to fetch assets for asset group {asset_group_id}: {e}")
        return {}, 0
    except Exception as e:
        print(f"❌ Error fetching software: {e}")
        logging.error(f"❌ Error fetching software: {e}")
        import traceback
        traceback.print_exc()
        return {}, 0


 
def get_installed_software_all_groups():
    """Get installed software from all available asset groups (one CSV per group)."""
    try:
        print("🔄 Fetching assets for default site 2 (page-by-page)...")
        # site-based export with page-by-page saving via get_installed_software_for_site
        get_installed_software_for_site(site_id=2)
        
    except Exception as e:
        print(f"❌ Error fetching all asset groups: {e}")
        logging.error(f"❌ Error fetching all asset groups: {e}")


def get_installed_software_multiple_groups(asset_group_ids):
    """Get installed software for each asset group ID separately and save one CSV per group."""
    try:
        print(f"🔄 Fetching installed software for {len(asset_group_ids)} asset groups: {asset_group_ids}")
        logging.info(f"🔄 Fetching installed software for multiple asset groups: {asset_group_ids}")

        processed_groups = 0
        for asset_group_id in asset_group_ids:
            print(f"\n{'='*60}")
            print(f"🔄 Processing Asset Group ID: {asset_group_id}")
            print(f"{'='*60}")

            # This call will also auto-save a CSV per group when data exists
            software_data, _ = get_installed_software(asset_group_id)
            if software_data:
                processed_groups += 1

        if processed_groups == 0:
            print(f"\nℹ️  No software found across the provided asset groups")
        else:
            print(f"\n✅ Completed. Generated CSV files for {processed_groups} asset group(s).")

    except Exception as e:
        print(f"❌ Error processing multiple asset groups: {e}")
        logging.error(f"❌ Error processing multiple asset groups: {e}")