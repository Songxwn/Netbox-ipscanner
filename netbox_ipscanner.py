import pynetbox, urllib3, networkscan, socket, ipaddress
from extras.scripts import Script

TOKEN='xxx'

NETBOXURL='https://your.netbox.address'

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning) #禁用安全警告

class IpScan(Script):
    # 这里是用户界面中的可选变量！
    class Meta:
        name = "IP 扫描器"
        description = "扫描可用前缀并更新 IPAM 中的 IP 地址"

    def run(self, data, commit):

        def reverse_lookup(ip):
            '''
            进行 DNS 反向查找并控制故障的迷你功能
            '''
            try:
                data = socket.gethostbyaddr(ip)
            except Exception:
                return '' # 优雅地失败
            if data[0] == '': #  如果没有名称
                return ''
            else:
                return data[0]

        nb = pynetbox.api(NETBOXURL, token=TOKEN)
        nb.http_session.verify = False # 禁用Netbox的证书检查

        subnets = nb.ipam.prefixes.all()  #提取所有前缀，格式为 x.x.x.x/yyy

        for subnet in subnets:
            if str(subnet.status) == 'Reserved': # 不扫描保留子网
                self.log_warning(f"Scan of {subnet.prefix} NOT done (is Reserved)")
                continue
            IPv4network = ipaddress.IPv4Network(subnet)
            mask = '/'+str(IPv4network.prefixlen)
            scan = networkscan.Networkscan(subnet)
            scan.run()
            self.log_info(f'Scan of {subnet} done.')

            # 从 Netbox 中提取地址信息
            netbox_addresses = dict()
            for ip in nb.ipam.ip_addresses.filter(parent=str(subnet)):
                netbox_addresses[str(ip)] = ip

            # 将未响应 ping 的每个 Netbox 条目标记为已删除的例程
            for address in IPv4network.hosts(): # 前缀为 x.x.x.x/yy 的每个地址
		        #self.log_debug(f'checking {address}...')
                netbox_address = netbox_addresses.get(address)
                if netbox_address != None: # 如果 IP 地址存在于 netbox // 如果不存在，则让它处于发现状态
                    if str(netbox_address).rpartition('/')[0] in scan.list_of_hosts_found:  # 如果他在 “活着 ”的名单中
                        pass # 什么也不做：它存在于 NB 中，并在 ping 列表中：好的，继续，稍后当您循环查看已响应的 IP 地址是否需要更新时，就会看到它。
			            #self.log_success(f"L'host {str(netbox_address).rpartition('/')[0]} esiste in netbox ed è stato pingato")
                    else: # 如果它存在于 netbox 中，但不在列表中，则将其标记为已废弃
                        self.log_failure(f"Host {str(netbox_address)} exists in netbox but not responding --> DEPRECATED")
                        nb.ipam.ip_addresses.update([{'id':netbox_address.id, 'status':'deprecated'},])
            ####

            if scan.list_of_hosts_found == []:
                self.log_warning(f'No host found in network {subnet}')
            else:
                self.log_success(f'IPs found: {scan.list_of_hosts_found}')
            for address1 in scan.list_of_hosts_found: # 对于 ping 列表中的每个 IP...
                ip_mask=str(address1)+mask
                current_in_netbox = netbox_addresses.get(ip_mask)
                #self.log_debug(f'pinged ip: {address1} mask: {mask} --> {ip_mask} // extracted ip from netbox: {current_in_netbox}')
                if current_in_netbox != None: # the pinged address is already present in the Netbox, mark it as Active and check the name if it has changed
                    if current_in_netbox.status.value != "active":
                        nb.ipam.ip_addresses.update([{'id':current_in_netbox.id, 'status':'active'},])
                    name = reverse_lookup(address1) # name resolution from DNS
                    if current_in_netbox.dns_name.lower() == name.lower(): # the names in Netbox and DNS match, do nothing
                        pass
                    else: # the names in Netbox and in DNS *DO NOT* match --> update Netbox with DNS name
                        self.log_success(f'Name for {address1} updated to {name}')
                        nb.ipam.ip_addresses.update([{'id':current_in_netbox.id, 'dns_name':name},])
                else: # the pinged address is NOT present in Netbox, I have to add it
                    name = reverse_lookup(address1) # name resolution from DNS
                    res = nb.ipam.ip_addresses.create(address=ip_mask, status='deprecated', dns_name=name)
                    if res:
                        self.log_success(f'Added {address1} - {name}')
                    else:
                        self.log_error(f'Adding {address1} - {name} FAILED')

