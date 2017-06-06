# Copyright (c) 2013 OpenStack Foundation
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from neutron_lib.api.definitions import portbindings
from neutron_lib import constants

from neutron.agent import securitygroups_rpc
from neutron.plugins.common import constants as p_constants
from neutron.plugins.ml2.drivers import mech_agent
from neutron.services.qos.drivers.linuxbridge import driver as lb_qos_driver


class LinuxbridgeMechanismDriver(mech_agent.SimpleAgentMechanismDriverBase):
    """Attach to networks using linuxbridge L2 agent.

    The LinuxbridgeMechanismDriver integrates the ml2 plugin with the
    linuxbridge L2 agent. Port binding with this driver requires the
    linuxbridge agent to be running on the port's host, and that agent
    to have connectivity to at least one segment of the port's
    network.
    """

    def __init__(self):
        sg_enabled = securitygroups_rpc.is_firewall_enabled()
        super(LinuxbridgeMechanismDriver, self).__init__(
            constants.AGENT_TYPE_LINUXBRIDGE,
            portbindings.VIF_TYPE_TAP,
            {portbindings.CAP_PORT_FILTER: sg_enabled})
        lb_qos_driver.register()

    def get_allowed_network_types(self, agent):
        return (agent['configurations'].get('tunnel_types', []) +
                [p_constants.TYPE_LOCAL, p_constants.TYPE_FLAT,
                 p_constants.TYPE_VLAN])

    def get_mappings(self, agent):
        mappings = dict(agent['configurations'].get('interface_mappings', {}),
                        **agent['configurations'].get('bridge_mappings', {}))
        return mappings

    def get_vif_type(self, context, agent, segment):
        # TODO(kevinbenton): remove this function after we no longer support
        # Ocata agents
        if not agent['configurations'].get('wires_compute_ports'):
            return portbindings.VIF_TYPE_BRIDGE
        return self.vif_type

    def check_vlan_transparency(self, context):
        """Linuxbridge driver vlan transparency support."""
        return True
