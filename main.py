import argparse
import time
from modules.workflow import auto_execute, show_reports, check_reports, show_asset_groups, get_installed_software, get_installed_software_multiple_groups, get_installed_software_all_groups

def main():
    parser = argparse.ArgumentParser(description="Workflow Automation Tool")
    parser.add_argument('--auto', action='store_true', help='Automatically execute workflows from YAML schedule')
    parser.add_argument('--show', nargs='?', const=10, help='Show available report IDs (default: 10, or specify "all")')
    parser.add_argument('--check', nargs=3, metavar=('report_id1', 'report_id2', 'receiver_email'),
                        help='Manually execute workflow include force generating with specified report IDs and receiver email (no host domain name)')
    parser.add_argument('--show-asset-groups', action='store_true', help='Show all available asset group IDs')
    parser.add_argument('--get-software', nargs='+', metavar='asset_group_id_or_all', 
                        help='Get installed software. Use "all" to fetch all asset groups, or pass one or more asset group IDs like: 1 2 3')
    

    args = parser.parse_args()

    if args.auto:
        auto_execute()
    elif args.show:
        limit = args.show if args.show == 'all' else int(args.show)
        show_reports(limit)

    elif args.check:
        try:
            report_id1 = int(args.check[0])
            report_id2 = int(args.check[1])
            receiver_email = args.check[2]
        except ValueError:
            print("❌ report_id1 and report_id2 must be integers.")
            return
        check_reports(report_id1, report_id2, receiver_email)

    elif args.show_asset_groups:
        show_asset_groups()

    elif args.get_software:
        try:
            if args.get_software[0].lower() == 'all':
                # Get software across all asset groups
                get_installed_software_all_groups()
            else:
                # Get software from specific asset group IDs
                asset_group_ids = []
                for arg in args.get_software:
                    try:
                        asset_group_ids.append(int(arg))
                    except ValueError:
                        print(f"❌ Invalid asset group ID: {arg}. Must be an integer.")
                        return
                
                if len(asset_group_ids) == 1:
                    # Single asset group
                    get_installed_software(asset_group_ids[0])
                else:
                    # Multiple asset groups
                    get_installed_software_multiple_groups(asset_group_ids)
                    
        except Exception as e:
            print(f"❌ Error processing asset group IDs: {e}")
            return



    else:
        parser.print_help()


if __name__ == "__main__":
    main()
