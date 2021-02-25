from mitmproxy import http, ctx
from multiprocessing import Lock
import socket
import requests
from urllib.parse import urlencode

class GetRequestInfoFilter:
    def __init__(self, filter_info):
        self.log_info = ""
        self.mutex = Lock()
        self.filter_info = filter_info
        self.response_file = None
        self.switch_on = False
        self.log_file = "log.txt"

    def log(self, info) -> None:
        self.log_info += f"{info}\n\n"

    def write_log(self, mode="a") -> None:
        self.mutex.acquire()
        with open(self.log_file, mode) as f:
            f.write(self.log_info)
        self.mutex.release()

    def is_target_flow(self, flow: http.HTTPFlow) -> bool:
        for info in self.filter_info:
            if info["str_in_url"] in flow.request.url:
                self.log_file = info["log_file"]
                self.switch_on = info["switch_on"]
                if info["response_file"] != None:
                    self.response_file = info["response_file"]
                return True
        else:
            return False

    def modify_response(self, flow: http.HTTPFlow) -> http.HTTPFlow:
        if self.switch_on and self.response_file:
            with open(self.response_file, "r") as f:
                flow.response.content = f.read().encode()
        return flow

    def get_curl(self,method, uri, headers, data) -> str:
        command = "curl -X {method} -H {headers} -d '{data}' '{uri}' --compressed --insecure"
        headers = ['"{0}: {1}"'.format(k, v) for k, v in headers.items()]
        headers = " -H ".join(headers)
        return command.format(method=method, headers=headers, data=data, uri=uri)

    def getIP(self,domain):
        myaddr = socket.getaddrinfo(domain, 'http')
        return myaddr[0][4][0]


    def isAlive(self, ip, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex((ip, port))
        if result == 0:
            flag = True  # 服务的端口是通的
        else:
            flag = False  # 服务器端口不通
        return flag

    def request(self, flow: http.HTTPFlow) -> None:
        return

    def response(self, flow: http.HTTPFlow) -> None:

        if self.is_target_flow(flow):
            timeCost = flow.response.timestamp_end - flow.request.timestamp_start
            timeTake = round(timeCost*1000)  # 请求耗时  四舍五入
            responseCode = flow.response.status_code
            # print(str(timeTake) + "   ----  "+ str(responseCode))
            if ((int(timeTake) > 800) | (int(responseCode) > 399)):
                method = flow.request.method
                host = flow.request.pretty_host
                url = flow.request.pretty_url
                headers = flow.request.headers
                data = ""
                # clientIp = flow.client_conn.ip_address[0].split(':')[3]
                clientIp = flow.client_conn.ip_address[0]
                ServerIp = self.getIP(flow.request.host)
                deviceId = flow.request.headers.get('deviceid')

                query = [i + "=" + flow.request.query[i] for i in flow.request.query]
                data = '&'.join(query)
                # self.log(f"——QUERY STRING——\n{data}")
                if flow.request.urlencoded_form:
                    form = [i + "=" + flow.request.urlencoded_form[i] for i in flow.request.urlencoded_form]
                    data = '&'.join(form)
                    # self.log(f"——FORM——\n{data}")
                curl = self.get_curl(method,url,headers,data)

                if self.isAlive("10.219.9.104",10000):
                    try:
                        headers = {
                                'Content-Type': 'application/x-www-form-urlencoded',
                                'Accept': '*/*'
                        }
                        uploadUrl = "http://*.*.*.*:10000/qabackend/uploadAbnormalInfo/"
                        uploadData = {'clientIP': str(clientIp),
                                      'user': "monkey",
                                      'hostIP': ServerIp,
                                      'host': host,
                                      'curl': curl,
                                      'responseCode': responseCode,
                                      'timeTake': timeTake,
                                      'requestUrl': url,
                                      'requestHeader': headers,
                                      'deviceId': deviceId,
                                      'requestInfo': '',
                                      }
                        res = requests.post(uploadUrl, data=urlencode(uploadData), headers=headers)
                    except Exception as ex:
                        print("出现如下异常%s" % ex)
                        pass



                # self.log_info = ""
                # self.log(f"——time-cost——\n{timeTake}")
                # self.log(f"——METHOD——\n{flow.request.method}")
                # self.log(f"——HOST——\n{flow.request.pretty_host}")
                # self.log(f"——URL——\n{flow.request.pretty_url}")
                # self.log(f"——REQUESTHEADER——\n{flow.request.headers}")
                # self.log(f"——Host——\n{flow.request.host}")
                # self.log(f"——data——\n{flow.request.data}")
                # self.log(f"——clientIp——\n{flow.client_conn.ip_address[0].split(':')[3]}")
                # self.log(f"——ServerIp——\n{self.getIP(flow.request.host)}")
                # self.log(f"——deviceId——\n{flow.request.headers.get('deviceid')}")
                # self.log(f"——responseCode——\n{flow.response.status_code}")
                # self.log(f"——curl——\n{curl}")
                #
                # self.write_log()
        return


filter_info = [
    {
        "str_in_url": ".xxx.com",
        "log_file": "filter.txt",
        "switch_on": True,
        "response_file": None,
    }
]
addons = [
    GetRequestInfoFilter(filter_info)
]
