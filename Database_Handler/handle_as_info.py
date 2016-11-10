import os, sys
import re
import ujson

class as_info_handle():
    def convert_to_json(self, mypath, filename_as_info):
        dict = {}
        try:
            with open(os.path.join(mypath, filename_as_info), 'r') as fp:
                lines = fp.readlines()
                for line in lines:
                    matchObj = re.match(r'AS(\d*)\s*(.*)', line, re.M | re.I)

                    if matchObj:
                        asn = str(matchObj.group(1))
                        info = str(matchObj.group(2))

                        dict['AS' + asn] = info

        except Exception as e:
            print(e)

        with open(os.path.join(mypath, filename_as_info + '.json'), 'w') as fp:
            ujson.dump(dict, fp)

