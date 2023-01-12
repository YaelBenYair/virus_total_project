import os
import argparse
import pickle
from vt_class import VTAnalyzer, UrlUserSelection






if __name__ == '__main__':

    # check whether this is the first time you run the app
    # if this is the first time - create a new class
    if not os.path.exists('db\\check.pickle'):
        vt_a = VTAnalyzer()
    else:
        # this is not the first time - we already have a DB
        # with data from the previous runs
        with open('db\\check.pickle', 'rb') as fh:
            vt_a = pickle.load(fh)

    parser = argparse.ArgumentParser(
        prog='VirusTotal scanner',
        description='The program allows to check a url with VT API and return analysis results\n'
                    'Url | require | Enter as many urls as you want separated by commas without spaces.\n'
                    '-s or --scan | optional | force scan\n'
                    '-k or --apikey | optional | can enter your api key for analyze\n'
                    '-d or --day | optional | set the maximum age for the urls before rescan in days. default - 182\n',
        epilog='Text at the bottom of help')

    parser.add_argument('url', type=str, help="URL to scan")
    parser.add_argument('-s', '--scan', action='store_true')
    parser.add_argument('-k', '--apikey', type=str)
    parser.add_argument('-d', '--day', type=int, help='Number of days before rescan')
    args = parser.parse_args()
    print(args.url, args.scan, args.apikey, args.day)

    url_user = UrlUserSelection(args.url, args.scan, args.apikey, args.day)
    url_user.run()

    # before exiting the program, persist the current state
    # of te system in the file, so next time it will be loaded
    with open('db\\check.pickle', 'wb') as fh:
        pickle.dump(vt_a, fh)
















