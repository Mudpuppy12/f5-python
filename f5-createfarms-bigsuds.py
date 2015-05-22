#!/usr/bin/env python
# Copyright 2014, Rackspace US, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# (c) 2014, Kevin Carter <kevin.carter@rackspace.com>
import argparse
import json
import os
import yaml
import pprint
try:
   import bigsuds
   import logging
   logging.getLogger('suds.client').setLevel(logging.CRITICAL)
except ImportError:
    print "BigSuds F5 API not installed. Pushing to F5 not supported"

import netaddr

SNAT_POOL = (
    'create ltm snatpool %(prefix_name)s_SNATPOOL { members replace-all-with {'
    ' %(snat_pool_addresses)s } }'
)

MONITORS = (
    'create ltm monitor mysql %(prefix_name)s_MON_GALERA { count 0 database'
    ' information_schema debug yes defaults-from mysql destination *:*'
    ' interval 30 time-until-up 0 timeout 91 username haproxy }'
)

NODES = (
    'create ltm node %(node_name)s { address %(container_address)s }'
)


PRIORITY_ENTRY = '{ priority-group %(priority_int)s }'

POOL_NODE = {
    'beginning': 'create ltm pool %(pool_name)s {'
                 ' load-balancing-mode fastest-node members replace-all-with'
                 ' { %(nodes)s }',
    'priority': 'min-active-members 1',
    'end': 'monitor %(mon_type)s }'
}

VIRTUAL_ENTRIES = (
    'create ltm virtual %(vs_name)s {'
    ' destination %(internal_lb_vip_address)s:%(port)s'
    ' ip-protocol tcp mask 255.255.255.255'
    ' pool %(pool_name)s profiles replace-all-with { fastL4 { } }'
    ' source 0.0.0.0/0 source-address-translation {'
    ' pool %(snat_pool)s type snat } }'
)


# This is a dict of all groups and their respected values / requirements
POOL_PARTS = {
    'galera': {
        'port': 3306,
        'backend_port': 3306,
        'mon_type': 'RPC_MON_GALERA',
        'priority': True,
        'group': 'galera',
        'hosts': []
    },
    'glance_api': {
        'port': 9292,
        'backend_port': 9292,
        'mon_type': 'http',
        'group': 'glance_api',
        'hosts': []
    },
    'glance_registry': {
        'port': 9191,
        'backend_port': 9191,
        'mon_type': 'http',
        'group': 'glance_registry',
        'hosts': []
    },
    'heat_api_cfn': {
        'port': 8000,
        'backend_port': 8000,
        'mon_type': 'http',
        'group': 'heat_api_cfn',
        'hosts': []
    },
    'heat_api_cloudwatch': {
        'port': 8003,
        'backend_port': 8003,
        'mon_type': 'http',
        'group': 'heat_api_cloudwatch',
        'hosts': []
    },
    'heat_api': {
        'port': 8004,
        'backend_port': 8004,
        'mon_type': 'http',
        'group': 'heat_api',
        'hosts': []
    },
    'keystone_admin': {
        'port': 35357,
        'backend_port': 35357,
        'mon_type': 'http',
        'group': 'keystone',
        'hosts': []
    },
    'keystone_service': {
        'port': 5000,
        'backend_port': 5000,
        'mon_type': 'http',
        'group': 'keystone',
        'hosts': []
    },
    'neutron_server': {
        'port': 9696,
        'backend_port': 9696,
        'mon_type': 'http',
        'group': 'neutron_server',
        'hosts': []
    },
    'nova_api_ec2': {
        'port': 8773,
        'backend_port': 8773,
        'mon_type': 'http',
        'group': 'nova_api_ec2',
        'hosts': []
    },
    'nova_api_metadata': {
        'port': 8775,
        'backend_port': 8775,
        'mon_type': 'http',
        'group': 'nova_api_metadata',
        'hosts': []
    },
    'nova_api_os_compute': {
        'port': 8774,
        'backend_port': 8774,
        'mon_type': 'http',
        'group': 'nova_api_os_compute',
        'hosts': []
    },
    'nova_spice_console': {
        'port': 6082,
        'backend_port': 6082,
        'mon_type': 'http',
        'group': 'nova_spice_console',
        'hosts': []
    },
    'cinder_api': {
        'port': 8776,
        'backend_port': 8776,
        'mon_type': 'http',
        'group': 'cinder_api',
        'hosts': []
    },
    'horizon': {
        'port': 80,
        'backend_port': 80,
        'mon_type': 'http',
        'group': 'horizon',
        'hosts': []
    },
    'horizon_ssl': {
        'port': 443,
        'backend_port': 443,
        'mon_type': 'tcp',
        'group': 'horizon',
        'hosts': []
    },
    'swift_proxy': {
        'port': 8080,
        'backend_port': 8080,
        'mon_type': 'http',
        'group': 'swift_proxy',
        'hosts': []
    },
    'elasticsearch': {
        'port': 9200,
        'backend_port': 9200,
        'mon_type': 'tcp',
        'group': 'elasticsearch',
        'hosts': []
    },
    'kibana': {
        'port': 8888,
        'backend_port': 80,
        'mon_type': 'http',
        'group': 'kibana',
        'priority': True,
        'hosts': []
    },
    'kibana_ssl': {
        'port': 8443,
        'backend_port': 443,
        'mon_type': 'tcp',
        'group': 'kibana',
        'priority': True,
        'hosts': []
    }
}


def recursive_host_get(inventory, group_name, host_dict=None):
    if host_dict is None:
        host_dict = {}

    inventory_group = inventory.get(group_name)

    try:
        if 'children' in inventory_group and inventory_group['children']:
           for child in inventory_group['children']:
            recursive_host_get(
                inventory=inventory, group_name=child, host_dict=host_dict)
    except:
          pass
    try:
        if inventory_group.get('hosts'):
           for host in inventory_group['hosts']:
            if host not in host_dict['hosts']:
                ca = inventory['_meta']['hostvars'][host]['container_address']
                node = {
                    'hostname': host,
                    'container_address': ca
                }
                host_dict['hosts'].append(node)
    except:
         pass

    return host_dict


def build_pool_parts(inventory):
    for key, value in POOL_PARTS.iteritems():
        recursive_host_get(
            inventory, group_name=value['group'], host_dict=value
        )

    return POOL_PARTS


def file_find(filename, user_file=None, pass_exception=False):
    """Return the path to a file.

    If no file is found the system will exit.
    The file lookup will be done in the following directories:
      /etc/rpc_deploy/
      $HOME/rpc_deploy/
      $(pwd)/rpc_deploy/

    :param filename: ``str``  Name of the file to find
    :param user_file: ``str`` Additional localtion to look in FIRST for a file
    """
    file_check = [
        os.path.join(
            '/etc', 'rpc_deploy', filename
        ),
        os.path.join(
            os.environ.get('HOME'), 'rpc_deploy', filename
        ),
        os.path.join(
            os.getcwd(), filename
        )
    ]

    if user_file is not None:
        file_check.insert(0, os.path.expanduser(user_file))

    for f in file_check:
        if os.path.isfile(f):
            return f
    else:
        if pass_exception is False:
            raise SystemExit('No file found at: %s' % file_check)
        else:
            return False


def args():
    """Setup argument Parsing."""
    parser = argparse.ArgumentParser(
        usage='%(prog)s',
        description='Rackspace Openstack, Inventory Generator',
        epilog='Inventory Generator Licensed "Apache 2.0"')

    parser.add_argument(
        '-f',
        '--file',
        help='Inventory file. Default: [ %(default)s ]',
        required=False,
        default='rpc_inventory.json'
    )

    parser.add_argument(
        '-p',
        '--prefix',
        help='Default is RPC, or supply Lab name for pool / virtual name creation.',
        required=False,
        default='RPC'
    )

    parser.add_argument(
        '-s',
        '--snat-pool-address',
        help='LB Main SNAT pool address for [ RPC_SNATPOOL ], for'
             ' multiple snat pool addresses comma seperate the ip'
             ' addresses. By default this IP will be .15 from within your'
             ' containers_cidr as found within inventory.',
        required=False,
        default=None
    )

    parser.add_argument(
        '-f5',
        help='Make changes directly to the F5 and not output to script',
        required=False,
        action='store_true',
        default=False
    )

    parser.add_argument(
        '-f5clear',
        help='Clear F5 config, then exit. Do not make changes only clear. Needs -f5 flag',
        required=False,
        action='store_true',
        default=False
    )
    parser.add_argument(
        '--limit-source',
        help='Limit available connections to the source IP for all source'
             ' limited entries.',
        required=False,
        default=None
    )

    parser.add_argument(
        '-e',
        '--export',
        help='Export the generated F5 configuration script.'
             ' Default: [ %(default)s ]',
        required=False,
        default=os.path.join(
            os.path.expanduser('~/'), 'rpc_f5_config.sh'
        )
    )

    return vars(parser.parse_args())


def f5_clearcfg(api,prefix):

    # Delete virtual servers first, starting on prefix name

    all_list    = api.LocalLB.VirtualServer.get_list()
    prefix_list = [s for s in all_list if any(xs in s for xs in [prefix])]

    if prefix_list != []:

        try:
            api.LocalLB.VirtualServer.delete_virtual_server(prefix_list)
        except bigsuds.OperationFailed, e:
            print e

    # Delete pools, starting with the prefix name

    all_list   = api.LocalLB.Pool.get_list()
    prefix_list = [s for s in all_list if any(xs in s for xs in [prefix])]

    if prefix_list != []:

        try:
            api.LocalLB.Pool.delete_pool(prefix_list)
        except bigsuds.OperationFailed, e:
            print e

    # Delete nodes, starting with prefix name

    all_list   = api.LocalLB.NodeAddressV2.get_list()
    prefix_list = [s for s in all_list if any(xs in s for xs in [prefix])]

    if prefix_list != []:

        try:
            api.LocalLB.NodeAddressV2.delete_node_address(prefix_list)
        except bigsuds.OperationFailed, e:
            print e

    # Delete all monitors, starting with the prefix name

    all_list   = api.LocalLB.Monitor.get_template_list()
    prefix_list = [s['template_name'] for s in all_list if any(xs in s['template_name'] for xs in [prefix])]

    if prefix_list != []:

        try:
            api.LocalLB.Monitor.delete_template(prefix_list)
        except bigsuds.OperationFailed, e:
            print e

    # Delete all snats, starting with the prefix name

    all_list   = api.LocalLB.SNATPool.get_list()
    prefix_list = [s for s in all_list if any(xs in s for xs in [prefix])]

    if prefix_list != []:

        try:
            api.LocalLB.SNATPool.delete_snat_pool(prefix_list)
        except bigsuds.OperationFailed, e:
            print e

def f5_create_virts(api,prefix,f5virts):

    definitions = []
    wildmasks   = []
    vs_resource = []
    vs_profile  = []
    vs_list     = []

    snat_name = prefix + "_SNATPOOL"

    for vs in f5virts:

        vs_list.append(vs)

        definitions.append( { 'name': vs,
                              'address': f5virts[vs]['internal_lb_vip_address'],
                              'port'   : f5virts[vs]['port'],
                              'protocol':'PROTOCOL_TCP'
                            })

        wildmasks.append("255.255.255.255")

        vs_resource.append({ 'type': 'RESOURCE_TYPE_POOL',
                             'default_pool_name': f5virts[vs]['pool_name']
                           })


        vs_profile.append( [{ 'profile_context':'PROFILE_CONTEXT_TYPE_ALL',
                             'profile_name': 'fastL4'}])

    try:
        api.LocalLB.VirtualServer.create(definitions,wildmasks,vs_resource,vs_profile)
    except bigsuds.OperationFailed, e:
        print e

    try:
        api.LocalLB.VirtualServer.set_snat_pool(vs_list, [snat_name] * len (vs_list))
    except bigsuds.OperationFailed, e:
        print e

def f5_create_pools(api,prefix, f5pool, partition="/Common"):

    pool_names   = []
    lb_method    = []
    lb_members   = []
    mon_type     = []
    tmp          = []
    lb_priorities = []
    lb_priority = []
    mam_list = []


    def member_parse(hosts,port):
        tmp = []
        for host in hosts:

            tmp.append({
                        'address': host['node_name'],
                        'port': port
            })


        return tmp

    for pool_name in f5pool:

        # skip making pools that have no members

        if f5pool[pool_name]['hosts'] == []:
            continue

        pool_names.append(pool_name)


        tmp = member_parse( f5pool[pool_name]['hosts'],f5pool[pool_name]['port'])
        lb_members.append(tmp)

        priority = 100
        lb_priority = []

        if f5pool[pool_name].has_key('priority'):
            mam_list.append(pool_name)

            # First member gets 100, next member a lesser ratio

            for member in tmp:
                lb_priority.append(priority)
                priority -=5
        else:
            # Things without priority are set to 0, So we can just mass dump the update through the api
            for member in tmp:
                lb_priority.append(0)

        lb_priorities.append(lb_priority)


        # quick fix to the template to use the localized monitor

        if f5pool[pool_name]['mon_type'] == 'RPC_MON_GALERA':
           f5pool[pool_name]['mon_type'] = prefix + '_MON_GALERA'

        mon_type.append({ 'pool_name': pool_name,
                          'monitor_rule': { 'type': 'MONITOR_RULE_TYPE_SINGLE',
                                            'quorum': 0,
                                            'monitor_templates':[f5pool[pool_name]['mon_type']]
                                          }
                         }
                       )

    lb_method = ['LB_METHOD_FASTEST_NODE_ADDRESS'] * len(pool_names)

    try:
        api.LocalLB.Pool.create_v2(pool_names,lb_method,lb_members)
    except bigsuds.OperationFailed, e:
        print e

    try:
        api.LocalLB.Pool.set_monitor_association(mon_type)
    except bigsuds.OperationFailed, e:
        print e

    try:
        api.LocalLB.Pool.set_member_priority(pool_names,lb_members,lb_priorities)
    except bigsuds.OperationFailed, e:
        print e

    try:
        api.LocalLB.Pool.set_minimum_active_member(mam_list, [1] * len(mam_list))
    except bigsuds.OperationFailed, e:
        print e

def  f5_create_nodes(api, prefix, f5node ):

     nodes = []
     addr = []
     limits = []

     for ip in f5node:
         nodes.append(f5node[ip])
         addr.append(ip)

     limits = [0] * len(nodes)

     try:
         api.LocalLB.NodeAddressV2.create(nodes,addr,limits)
     except bigsuds.OperationFailed, e:
        print e

def f5_create_monitor(api, prefix):

    ## This took forever to figure out, the documents are clear as mud.

   template_name =  prefix + "_MON_" + "GALERA"

   api.LocalLB.Monitor.create_template(
        [
        { 'template_name': [template_name],
          'template_type': 'TTYPE_MYSQL'
        }
        ],
        [ { 'parent_template': "/Common/mysql",
            'interval':30,
            'timeout' :91,
            'dest_ipport':
                             { 'address_type': 'ATYPE_STAR_ADDRESS_STAR_PORT',
                               'ipport': {
                                           'address': "0.0.0.0",
                                           'port': 0
                               }

                             },
            'is_read_only':False,
            'is_directly_usable':True
           }
         ]
    )

   values = [

                         {'type':'STYPE_USERNAME',
                          'value': 'haproxy'
                         },
                         {'type': 'STYPE_DATABASE',
                          'value': "information_schema"
                         },
                         {'type': 'STYPE_DEBUG',
                          'value': 'Yes'
                         },
                         {'type': 'STYPE_DB_COUNT',
                          'value': 0
                         },
            ]


   # build the template names in the way the API can update them. It's a 1 to 1 value update. Not a 1 to may, so
   # We need to pad the names for each value even it's the same template name.

   template_names = [template_name] * len(values)

   api.LocalLB.Monitor.set_template_string_property(
            template_names, values)


def f5_create_snatpool(api,prefix,snat):
    """ Love working with F5.. So much documented goodness..."""

    snat_pools = []
    translation_addresses = []

    snat_pools.append(prefix + "_SNATPOOL")
    translation_addresses.append(snat.split())

    try:
      api.LocalLB.SNATPool.create_v2(snat_pools,translation_addresses)
    except bigsuds.OperationFailed, e:
      print e

def main():
    """Run the main application."""
    # Parse user args
    user_args = args()

    prefix_name=user_args['prefix'].upper()

    # Get the contents of the system environment json
    environment_file = file_find(filename=user_args['file'])
    with open(environment_file, 'rb') as f:
        inventory_json = json.loads(f.read())

    nodes = []
    pools = []
    virts = []

    f5node = {}
    f5pool = {}
    f5virt = {}


    pool_parts = build_pool_parts(inventory=inventory_json)
    lb_vip_address = inventory_json['all']['vars']['internal_lb_vip_address']

    for key, value in pool_parts.iteritems():
        value['group_name'] = key.upper()
        value['vs_name'] = '%s_VS_%s' % (
            prefix_name, value['group_name']
        )
        value['pool_name'] = '%s_POOL_%s' % (
            prefix_name, value['group_name']
        )

        node_data = []
        priority = 100

        for node in value['hosts']:
            node['node_name'] = '%s_NODE_%s' % (prefix_name, node['hostname'])
            nodes.append('%s\n' % NODES % node)

            f5node[node['container_address'] ]= node['node_name']

            virt = (
                '%s\n' % VIRTUAL_ENTRIES % {
                    'port': value['port'],
                    'vs_name': value['vs_name'],
                    'pool_name': value['pool_name'],
                    'internal_lb_vip_address': lb_vip_address,
                    'snat_pool': prefix_name + "_SNATPOOL"
                }
            )

            if virt not in virts:
                virts.append(virt)

            f5virt[value['vs_name']] = {
                'port': value['port'],
                'pool_name': value['pool_name'],
                'internal_lb_vip_address': lb_vip_address,
                'snat_pool': prefix_name + "_SNATPOOL",
                'destination': lb_vip_address + ":" + str(value['port'])
            }

            if value.get('priority') is True:
                node_data.append(
                    '%s:%s %s' % (
                        node['node_name'],
                        value['backend_port'],
                        PRIORITY_ENTRY % {'priority_int': priority}
                    )
                )
                priority -= 5
            else:
                node_data.append(
                    '%s:%s' % (
                        node['node_name'],
                        value['backend_port']
                    )
                )


        value['nodes'] = ' '.join(node_data)

        f5pool[value['pool_name']]= value

        pool_node = [POOL_NODE['beginning'] % value]
        if value.get('priority') is True:
            pool_node.append(POOL_NODE['priority'])

        pool_node.append(POOL_NODE['end'] % value)
        pools.append('%s\n' % ' '.join(pool_node))


    # define the SNAT pool address
    snat_pool_adds = user_args.get('snat_pool_address')
    if snat_pool_adds is None:
        container_cidr = inventory_json['all']['vars']['container_cidr']
        network = netaddr.IPNetwork(container_cidr)
        snat_pool_adds = str(network[15])

    snat_pool_addresses = ' '.join(snat_pool_adds.split(','))
    snat_pool = '%s\n' % SNAT_POOL % {
        'prefix_name': prefix_name,
        'snat_pool_addresses': snat_pool_addresses
    }


    if not user_args['f5']:

      script = [
          '#!/usr/bin/bash\n',
          snat_pool,
          '%s\n' % MONITORS % {'prefix_name': prefix_name}
      ]

      script.extend(nodes)
      script.extend(pools)
      script.extend(virts)

      with open(user_args['export'], 'wb') as f:
          f.writelines(script)

    if user_args['f5']:

        import getpass
        import  GPGYaml.GPGYaml as GPGYaml

        gpg_keyfile = "inventory.asc"
        encrypt_for = "BFBE9993DAC47736C24FA06F60814374C9C8A9AA"
        data_dir = "./data"

        passphrase = getpass.getpass()

        with open(data_dir + "/" + 'labs_gpg.yml') as data_file:
         lab_data = GPGYaml.load(data_file,key=passphrase,keyfile=gpg_keyfile,encrypt_for=encrypt_for)

         userid   = lab_data[prefix_name]['LB']['id']
         password = lab_data[prefix_name]['LB']['passwd']
         ip       = lab_data[prefix_name]['LB']['IP']

        api =bigsuds.BIGIP(ip,userid,password,debug=True)

        if user_args['f5clear']:
           print "Clearing old configs (if any) and exiting."
           f5_clearcfg(api,prefix_name)
           exit()

        print "Clearing old configs (if any)"
        f5_clearcfg(api,prefix_name)

        print "Creating snat pools"
        f5_create_snatpool(api, prefix_name,snat_pool_addresses,)

        print "Creating GALERA Monitor"
        f5_create_monitor(api, prefix_name)

        print "Creating Nodes"
        f5_create_nodes(api, prefix_name, f5node)

        print "Creating pools"
        f5_create_pools(api, prefix_name, f5pool)

        print "Creating VS's"
        f5_create_virts(api,prefix_name,f5virt)


if __name__ == "__main__":
    main()
