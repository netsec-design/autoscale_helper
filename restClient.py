import json
import time
import requests
from datetime import datetime
# Disable  InsecureRequestWarning: Unverified HTTPS request is being made.
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class ResourceException(BaseException):
    READ_ONLY = 'read-only'
    NAME_EXISTS = 'name-exists'
    INVALID_OBJECT_NAME = 'invalid-object-name'
    GENERIC = 'generic'

    def __init__(self, code, message=None):
        self.code = code
        self.message = message


class FMCRestClient():
    def __init__(self, server, username=None, password=None, auth_token=None, domain='default', list_multithreads=None):
        self.server = server
        self.username = username
        self.password = password
        self.auth_token = auth_token
        self.reauth_count = 0
        if domain is None:
            domain = 'default'
        self.domain = domain
        if not self.auth_token:
            self.auth_token = self.get_auth_token()
        # disabled multithreading as its has some issues and we
        # now have a way to incease the page limit to order of thousang
        self.list_multithreads = None

    def get_auth_token(self):
        api_auth_path = "/api/fmc_platform/v1/auth/generatetoken"
        auth_url = self.server + api_auth_path
        try:
            # Download SSL certificates from your FMC first and provide its path for verification.
            # r = requests.post(auth_url, headers=headers, auth=requests.auth.HTTPBasicAuth(username,password), verify='/path/to/ssl_certificate/')
            headers = {'Content-Type': 'application/json'}
            print('Connecting to ' + auth_url)
            response = requests.post(auth_url, headers=headers,
                                     auth=requests.auth.HTTPBasicAuth(self.username, self.password), verify=False)
            auth_headers = response.headers
            auth_token = auth_headers.get('X-auth-access-token', default=None)
            if auth_token == None:
                print('Error: auth_token not found.')
                raise Exception('auth_token not found')
            else:
                print('Got auth_token - ' + auth_token)
            return auth_token
        except Exception as err:
            # print ('Error in generating auth token --> '+str(err))
            raise Exception('Error in generating auth token --> ' + str(err))

    def rest_call(self, method, url_path, post_data=None, offset=0):
        start_time = datetime.now().replace(microsecond=0)
        end_time = start_time
        vars = {'DOMAIN': self.domain}
        url = self.server + url_path.format(**vars)
        if (url[-1] == '/'):
            url = url[:-1]
        print('REST Call: [' + method.upper() + '] ' + url + '?offset=' + str(offset))
        headers = {'Content-Type': 'application/json', 'X-auth-access-token': self.auth_token}
        print(headers)
        try:
            return self._rest_call(method, url, post_data, headers, offset)
        except Exception as e:
            print('REST called failed: ' + str(e))
            raise e
        finally:
            end_time = datetime.now().replace(microsecond=0)
            print('REST call completed in ' + str(end_time - start_time))

    def _http_request(self, method, url, post_data, headers, offset=0):
        response = None
        try:
            if method in ['post', 'create']:
                print('Post data ' + post_data)
                response = requests.post(url, data=post_data, headers=headers, verify=False)
            elif method in ['put']:
                print('Post data ' + post_data)
                response = requests.put(url, data=post_data, headers=headers, verify=False)
            elif method == 'get':
                response = requests.get(url, headers=headers, verify=False)
            elif method == 'delete':
                response = requests.delete(url, headers=headers, verify=False)
            elif method == 'list':
                params = {'limit': 15000, 'offset': offset}
                response = requests.get(url, headers=headers, params=params, verify=False)
            else:
                raise Exception('Unknown method ' + method)
        except:
            raise
        return response

    def _rest_call(self, method, url, post_data, headers, offset=0):
        response = None
        data = None
        try:
            response = self._http_request(method, url, post_data, headers, offset)
            if response is not None:
                status_code = response.status_code
                data = response.text
                # print('Status code is: ' + str(status_code))
                if status_code == 200 or status_code == 201 or status_code == 202:
                    # print(method + ' was successful...')
                    json_resp = json.loads(data)
                    print(json.dumps(json_resp,sort_keys=True,indent=4, separators=(',', ': ')))
                    return json_resp
                elif status_code == 401:
                    print('Re-authenticating ...')
                    if response: response.close()
                    # response = None
                    if (self.reauth_count <= 3):
                        self.auth_token = self.get_auth_token()
                        headers = {'Content-Type': 'application/json', 'X-auth-refresh-token': self.auth_token}

                        # self._rest_call(method, url, post_data, headers, offset)
                        response = self._http_request(method, url, post_data, headers, offset)
                        # self._rest_call(method, url, post_data, headers, offset)
                        # self._rest_call(method, resource)
                elif status_code == 404 and method == 'list':  # today REST API returns 404 when the list is empty
                    return ([], 0)
                elif status_code == 405 and (method == 'create' or method == 'post'):
                    raise ResourceException(ResourceException.READ_ONLY)
                elif (status_code == 400 or status_code == 500) and (method == 'create' or method == 'post'):
                    json_resp = json.loads(data)
                    desc = json_resp['error']['messages'][0]['description']
                    NAME_EXISTS_ERROR = ['name already exists', 'conflicts with predefined name on device']
                    for error in NAME_EXISTS_ERROR:
                        if error in desc:
                            raise ResourceException(ResourceException.NAME_EXISTS)
                    INVALID_NAME_ERROR = ['Invalid Object Name']
                    for error in INVALID_NAME_ERROR:
                        if error in desc:
                            raise ResourceException(ResourceException.INVALID_OBJECT_NAME)
                    raise ResourceException(ResourceException.GENERIC, desc)
                elif (status_code == 429) and (method == 'create' or method == 'post'):
                    json_resp = json.loads(data)
                    reasonPhrase = json_resp['reasonPhrase']
                    TOO_MANY_REQUESTS = 'Too Many Requests'
                    if TOO_MANY_REQUESTS == reasonPhrase:
                        time.sleep(5)
                        self._rest_call(method, url, post_data, headers, offset)
                else:
                    raise Exception('[' + method.upper() + '] ' + response.url + '\n' \
                                                                                 '\tHTTP Error: ' + str(
                        response.status_code) + ', Response Data: ' + response.text)
                    # response.raise_for_status()
                    # print ('Error occurred in --> ' + response)
        except requests.exceptions.HTTPError as err:
            print('Error in connection --> ' + str(err))
            raise Exception(str(err))
        except ValueError as e:
            print('Error with response ' + str(data))
            raise e
        finally:
            if response: response.close()

    def _list(self, resource, offset=None):
        url_path = resource.get_api_path()
        print (url_path)
        json_resp = self.rest_call('list', url_path, offset=offset)
        objs = []
        # print(json_resp['items'])
        if json_resp:
            if 'items' in json_resp:
                for json_obj in json_resp['items']:
                    obj = resource.__class__(json_obj['name'])
                    obj.json_load(json_obj)
                    objs.append(obj)
                    # print(objs)
            return (objs, int(json_resp['paging']['pages']))
        else:
            json_resp = self.rest_call('list', url_path, offset=offset)

    ######## Raw HTTP calls ###########
    ## these uses the raw payload which is json ##
    def get(self, url_path):
        # To be implemented
        return self.rest_call('get', url_path)

    def post(self, url_path, data):
        # To be implemented
        return self.rest_call('post', url_path, data)

    def put(self, url_path, data):
        return self.rest_call('put', url_path, data)

    def delete(self, url_path):
        return self.rest_call('delete', url_path)

    ######## rest abstractions ###########
    def create(self, resource):
        #print("create called")
        url_path = resource.get_api_path()
        post_data = resource.json(pretty=False)
        json_resp = self.post(url_path, post_data)
        resource.json_load(json_resp)
        return resource

    def load(self, resource):
        url_path = resource.get_api_path()
        if resource.id:
            url_path += '/' + str(resource.id)
        json_resp = self.get(url_path)
        resource.json_load(json_resp)
        return resource

    def update(self, resource):
        url_path = resource.get_api_path()
        post_data = resource.json(pretty=False)
        json_resp = self.put(url_path, post_data)
        resource.json_load(json_resp)
        return resource

    def remove(self, resource):
        url_path = resource.get_api_path()
        if resource.id:
            url_path += '/' + str(resource.id)
        json_resp = self.delete(url_path)
        return json_resp

    def list(self, resource, offset=0):
        objs = []
        result = self._list(resource, offset=offset)
        if result is not None:
            objs.extend(result[0])
            self.inList = []
            pages = result[1] - 1  # we already read one page
            if pages > 2 and (self.list_multithreads is not None and self.list_multithreads > 0):
                import concurrent.futures
                from multiprocessing import Queue
                self.listOutQ = Queue()
                print('Entered in to mutlithreaded list retrieval mode ...')
                page_size = len(result[0])
                # no_threads = min(int(pages/5), self.list_multithreads)
                no_threads = self.list_multithreads
                page = 0
                while page < pages:
                    page += 1
                    self.inList.append((resource, page * page_size))

                print('list in ' + str(self.inList))
                with concurrent.futures.ThreadPoolExecutor(max_workers=no_threads) as executor:
                    for result in executor.map(self.list_worker, self.inList):
                        print('processing result ...')
                        if result:
                            print('Adding objs to list ' + str(len(result[0])))
                            objs.extend(result[0])
                            # self.listOutQ.put(result[0])
                            # print('Got all the pages')
                            # while not self.listOutQ.empty():
                            #    objs.extend(self.listOutQ.get())

            else:
                while pages > 0:
                    if result is not None:
                        offset += len(result[0])
                        print('pages ' + str(pages))
                        print('offset ' + str(offset) + ' len(objs) ' + str(len(objs)))
                        result = self._list(resource, offset=offset)
                        if result is not None:
                            pages -= 1
                            objs.extend(result[0])
                        else:
                            offset -= 1000
                            print('pages ' + str(pages))
                            print('offset ' + str(offset) + ' len(objs) ' + str(len(objs)))
                            result = self._list(resource, offset=offset)
            return objs
        else:
            result = self._list(resource, offset=offset)

    def list_worker(self, args):
        resource = args[0]
        url_path = resource.get_api_path()
        offset = args[1]
        result = self.list(url_path, offset=offset)
        if result:
            self.listOutQ.put(result[0])
