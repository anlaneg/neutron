# Copyright (c) 2013 OpenStack Foundation.
# All rights reserved.
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

from neutron_lib.api.definitions import multiprovidernet as apidef
from neutron_lib.api import extensions


class Multiprovidernet(extensions.APIExtensionDescriptor):
    """Extension class supporting multiple provider networks.

    This class is used by neutron's extension framework to make
    metadata about the multiple provider network extension available to
    clients. No new resources are defined by this extension. Instead,
    the existing network resource's request and response messages are
    extended with 'segments' attribute.

    With admin rights, network dictionaries returned will also include
    'segments' attribute.
    """

    api_definition = apidef
