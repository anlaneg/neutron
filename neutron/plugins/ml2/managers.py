# encoding:utf-8
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

from neutron_lib.api.definitions import external_net as extnet_apidef
from neutron_lib.api.definitions import multiprovidernet as mpnet_apidef
from neutron_lib.api.definitions import portbindings
from neutron_lib.api.definitions import provider_net as provider
from neutron_lib.api import validators
from neutron_lib import constants
from neutron_lib import exceptions as exc
from neutron_lib.exceptions import multiprovidernet as mpnet_exc
from neutron_lib.exceptions import vlantransparent as vlan_exc
from neutron_lib.plugins.ml2 import api
from oslo_config import cfg
from oslo_log import log
from oslo_utils import excutils
import stevedore

from neutron._i18n import _
from neutron.conf.plugins.ml2 import config
from neutron.db import api as db_api
from neutron.db import segments_db
from neutron.plugins.ml2.common import exceptions as ml2_exc
from neutron.plugins.ml2 import models

LOG = log.getLogger(__name__)

MAX_BINDING_LEVELS = 10
config.register_ml2_plugin_opts()


class TypeManager(stevedore.named.NamedExtensionManager):
    """Manage network segment types using drivers."""
    #管理网络段类型驱动，例如vxlan,vlan等
    def __init__(self):
        # Mapping from type name to DriverManager
        self.drivers = {}

        LOG.info("Configured type driver names: %s",
                 cfg.CONF.ml2.type_drivers)
        super(TypeManager, self).__init__('neutron.ml2.type_drivers',
                                          cfg.CONF.ml2.type_drivers,#要求载入type_drivers中指明的drivers
                                          invoke_on_load=True)
        LOG.info("Loaded type driver names: %s", self.names())
        self._register_types()
        self._check_tenant_network_types(cfg.CONF.ml2.tenant_network_types)
        self._check_external_network_type(cfg.CONF.ml2.external_network_type)

    def _register_types(self):
        for ext in self:
            #遍历加载进来的extension
            network_type = ext.obj.get_type()
            #防止重复加载
            if network_type in self.drivers:
                LOG.error("Type driver '%(new_driver)s' ignored because"
                          " type driver '%(old_driver)s' is already"
                          " registered for type '%(type)s'",
                          {'new_driver': ext.name,
                           'old_driver': self.drivers[network_type].name,
                           'type': network_type})
            else:
                #注册此类型的driver,例如vlan:neutron.plugins.ml2.drivers.type_vlan:VlanTypeDriver
                self.drivers[network_type] = ext
        LOG.info("Registered types: %s", self.drivers.keys())

    def _check_tenant_network_types(self, types):
        self.tenant_network_types = []
        for network_type in types:
            if network_type in self.drivers:
                self.tenant_network_types.append(network_type)
            else:
                #没有加载此驱动，但租户网络需要，配置错误，退出
                LOG.error("No type driver for tenant network_type: %s. "
                          "Service terminated!", network_type)
                raise SystemExit(1)
        LOG.info("Tenant network_types: %s", self.tenant_network_types)

    def _check_external_network_type(self, ext_network_type):
        #查看外部网络类型是否满足
        if ext_network_type and ext_network_type not in self.drivers:
            LOG.error("No type driver for external network_type: %s. "
                      "Service terminated!", ext_network_type)
            raise SystemExit(1)

    def _process_provider_segment(self, segment):
        #segment必须指出网络类型，物理网络，以及seg_id
        (network_type, physical_network,
         segmentation_id) = (self._get_attribute(segment, attr)
                             for attr in provider.ATTRIBUTES)

        if validators.is_attr_set(network_type):
            segment = {api.NETWORK_TYPE: network_type,
                       api.PHYSICAL_NETWORK: physical_network,
                       api.SEGMENTATION_ID: segmentation_id}
            #检查配置是否合法
            self.validate_provider_segment(segment)
            return segment

        msg = _("network_type required")
        raise exc.InvalidInput(error_message=msg)

    def _process_provider_create(self, network):
        if any(validators.is_attr_set(network.get(attr))
               for attr in provider.ATTRIBUTES):
            # Verify that multiprovider and provider attributes are not set
            # at the same time.
            if validators.is_attr_set(network.get(mpnet_apidef.SEGMENTS)):
                raise mpnet_exc.SegmentsSetInConjunctionWithProviders()
            segment = self._get_provider_segment(network)
            return [self._process_provider_segment(segment)]
        elif validators.is_attr_set(network.get(mpnet_apidef.SEGMENTS)):
            #采用的是segments方式
            segments = [self._process_provider_segment(s)
                        for s in network[mpnet_apidef.SEGMENTS]]
            mpnet_apidef.check_duplicate_segments(
                segments, self.is_partial_segment)
            return segments

    def _match_segment(self, segment, filters):
        return all(not filters.get(attr) or segment.get(attr) in filters[attr]
                   for attr in provider.ATTRIBUTES)

    def _get_provider_segment(self, network):
        # TODO(manishg): Placeholder method
        # Code intended for operating on a provider segment should use
        # this method to extract the segment, even though currently the
        # segment attributes are part of the network dictionary. In the
        # future, network and segment information will be decoupled and
        # here we will do the job of extracting the segment information.
        return network

    def network_matches_filters(self, network, filters):
        if not filters:
            return True
        if any(validators.is_attr_set(network.get(attr))
               for attr in provider.ATTRIBUTES):
            segments = [self._get_provider_segment(network)]
        elif validators.is_attr_set(network.get(mpnet_apidef.SEGMENTS)):
            segments = self._get_attribute(network, mpnet_apidef.SEGMENTS)
        else:
            return True
        return any(self._match_segment(s, filters) for s in segments)

    def _get_attribute(self, attrs, key):
        value = attrs.get(key)
        if value is constants.ATTR_NOT_SPECIFIED:
            value = None
        return value

    def extend_network_dict_provider(self, context, network):
        # this method is left for backward compat even though it would be
        # easy to change the callers in tree to use the bulk function
        return self.extend_networks_dict_provider(context, [network])

    def extend_networks_dict_provider(self, context, networks):
        ids = [network['id'] for network in networks]
        net_segments = segments_db.get_networks_segments(context, ids)
        for network in networks:
            segments = net_segments[network['id']]
            self._extend_network_dict_provider(network, segments)

    #扩充network的结果集字段，添加segments信息
    def _extend_network_dict_provider(self, network, segments):
        if not segments:
            LOG.debug("Network %s has no segments", network['id'])
            for attr in provider.ATTRIBUTES:
                network[attr] = None
        elif len(segments) > 1:
            network[mpnet_apidef.SEGMENTS] = [
                {provider.NETWORK_TYPE: segment[api.NETWORK_TYPE],
                 provider.PHYSICAL_NETWORK: segment[api.PHYSICAL_NETWORK],
                 provider.SEGMENTATION_ID: segment[api.SEGMENTATION_ID]}
                for segment in segments]
        else:
            segment = segments[0]
            network[provider.NETWORK_TYPE] = segment[api.NETWORK_TYPE]
            network[provider.PHYSICAL_NETWORK] = segment[
                api.PHYSICAL_NETWORK]
            network[provider.SEGMENTATION_ID] = segment[
                api.SEGMENTATION_ID]

    def initialize(self):
        for network_type, driver in self.drivers.items():
            LOG.info("Initializing driver for type '%s'", network_type)
            driver.obj.initialize()

    def _add_network_segment(self, context, network_id, segment,
                             segment_index=0):
        #保存申请好的网络段
        segments_db.add_network_segment(
            context, network_id, segment, segment_index)

    def create_network_segments(self, context, network, tenant_id):
        """Call type drivers to create network segments."""
        #分配一个网络段
        segments = self._process_provider_create(network)
        with db_api.context_manager.writer.using(context):
            network_id = network['id']
            if segments:
                #segments用户已要求
                for segment_index, segment in enumerate(segments):
                    #尝试预留
                    segment = self.reserve_provider_segment(
                        context, segment)
                    self._add_network_segment(context, network_id, segment,
                                              segment_index)
            elif (cfg.CONF.ml2.external_network_type and
                  self._get_attribute(network, extnet_apidef.EXTERNAL)):
                #配置了external_network_type且当前当前network为external
                segment = self._allocate_ext_net_segment(context)
                self._add_network_segment(context, network_id, segment)
            else:
                #未指定segments,需要为租户自动申请
                segment = self._allocate_tenant_net_segment(context)
                self._add_network_segment(context, network_id, segment)

    def reserve_network_segment(self, context, segment_data):
        """Call type drivers to reserve a network segment."""
        # Validate the data of segment
        if not validators.is_attr_set(segment_data[api.NETWORK_TYPE]):
            msg = _("network_type required")
            raise exc.InvalidInput(error_message=msg)

        net_type = self._get_attribute(segment_data, api.NETWORK_TYPE)
        phys_net = self._get_attribute(segment_data, api.PHYSICAL_NETWORK)
        seg_id = self._get_attribute(segment_data, api.SEGMENTATION_ID)
        segment = {api.NETWORK_TYPE: net_type,
                   api.PHYSICAL_NETWORK: phys_net,
                   api.SEGMENTATION_ID: seg_id}

        self.validate_provider_segment(segment)

        # Reserve segment in type driver
        with db_api.context_manager.writer.using(context):
            return self.reserve_provider_segment(context, segment)

    def is_partial_segment(self, segment):
        network_type = segment[api.NETWORK_TYPE]
        driver = self.drivers.get(network_type)
        if driver:
            return driver.obj.is_partial_segment(segment)
        else:
            msg = _("network_type value '%s' not supported") % network_type
            raise exc.InvalidInput(error_message=msg)

    def validate_provider_segment(self, segment):
        network_type = segment[api.NETWORK_TYPE]
        driver = self.drivers.get(network_type)
        if driver:
            driver.obj.validate_provider_segment(segment)
        else:
            msg = _("network_type value '%s' not supported") % network_type
            raise exc.InvalidInput(error_message=msg)

    def reserve_provider_segment(self, context, segment):
        network_type = segment.get(api.NETWORK_TYPE)
        driver = self.drivers.get(network_type)
        if isinstance(driver.obj, api.TypeDriver):
            return driver.obj.reserve_provider_segment(context.session,
                                                       segment)
        else:
            return driver.obj.reserve_provider_segment(context,
                                                       segment)

    def _allocate_segment(self, context, network_type):
        #分配网络segment
        driver = self.drivers.get(network_type)
        if isinstance(driver.obj, api.TypeDriver):
            return driver.obj.allocate_tenant_segment(context.session)
        else:
            return driver.obj.allocate_tenant_segment(context)

    def _allocate_tenant_net_segment(self, context):
        #尝试配置的所有租户网络类型，如果有一个可以分配成功，则返回
        for network_type in self.tenant_network_types:
            segment = self._allocate_segment(context, network_type)
            if segment:
                return segment
        raise exc.NoNetworkAvailable()

    def _allocate_ext_net_segment(self, context):
        #申请外部网络段
        network_type = cfg.CONF.ml2.external_network_type
        segment = self._allocate_segment(context, network_type)
        if segment:
            return segment
        raise exc.NoNetworkAvailable()

    def release_network_segments(self, context, network_id):
        segments = segments_db.get_network_segments(context, network_id,
                                                    filter_dynamic=None)

        for segment in segments:
            self.release_network_segment(context, segment)

    def release_network_segment(self, context, segment):
        network_type = segment.get(api.NETWORK_TYPE)
        driver = self.drivers.get(network_type)
        if driver:
            if isinstance(driver.obj, api.TypeDriver):
                driver.obj.release_segment(context.session, segment)
            else:
                driver.obj.release_segment(context, segment)
        else:
            LOG.error("Failed to release segment '%s' because "
                      "network type is not supported.", segment)

    def allocate_dynamic_segment(self, context, network_id, segment):
        """Allocate a dynamic segment using a partial or full segment dict."""
        dynamic_segment = segments_db.get_dynamic_segment(
            context, network_id, segment.get(api.PHYSICAL_NETWORK),
            segment.get(api.SEGMENTATION_ID))

        if dynamic_segment:
            return dynamic_segment

        driver = self.drivers.get(segment.get(api.NETWORK_TYPE))
        if isinstance(driver.obj, api.TypeDriver):
            dynamic_segment = driver.obj.reserve_provider_segment(
                context.session, segment)
        else:
            dynamic_segment = driver.obj.reserve_provider_segment(
                context, segment)
        segments_db.add_network_segment(context, network_id, dynamic_segment,
                                        is_dynamic=True)
        return dynamic_segment

    def release_dynamic_segment(self, context, segment_id):
        """Delete a dynamic segment."""
        segment = segments_db.get_segment_by_id(context, segment_id)
        if segment:
            driver = self.drivers.get(segment.get(api.NETWORK_TYPE))
            if driver:
                if isinstance(driver.obj, api.TypeDriver):
                    driver.obj.release_segment(context.session, segment)
                else:
                    driver.obj.release_segment(context, segment)
                segments_db.delete_network_segment(context, segment_id)
            else:
                LOG.error("Failed to release segment '%s' because "
                          "network type is not supported.", segment)
        else:
            LOG.debug("No segment found with id %(segment_id)s", segment_id)


class MechanismManager(stevedore.named.NamedExtensionManager):
    """Manage networking mechanisms using drivers."""
    #管理网络机制，例如openvswitch = neutron.plugins.ml2.drivers.openvswitch.mech_driver.mech_openvswitch:OpenvswitchMechanismDriver
    def __init__(self):
        # Registered mechanism drivers, keyed by name.
        self.mech_drivers = {}
        # Ordered list of mechanism drivers, defining
        # the order in which the drivers are called.
        self.ordered_mech_drivers = []

        LOG.info("Configured mechanism driver names: %s",
                 cfg.CONF.ml2.mechanism_drivers)
        super(MechanismManager, self).__init__(
            'neutron.ml2.mechanism_drivers',
            cfg.CONF.ml2.mechanism_drivers,#加载网络机制，例如走linux bridge方式，或者走ovs方式
            invoke_on_load=True,
            name_order=True,
            on_missing_entrypoints_callback=self._driver_not_found,
            on_load_failure_callback=self._driver_not_loaded
        )
        LOG.info("Loaded mechanism driver names: %s", self.names())
        self._register_mechanisms()
        self.host_filtering_supported = self.is_host_filtering_supported()
        if not self.host_filtering_supported:
            LOG.info("No mechanism drivers provide segment reachability "
                     "information for agent scheduling.")

    def _driver_not_found(self, names):
        msg = (_("The following mechanism drivers were not found: %s")
               % names)
        LOG.critical(msg)
        raise SystemExit(msg)

    def _driver_not_loaded(self, manager, entrypoint, exception):
        LOG.critical("The '%(entrypoint)s' entrypoint could not be"
                     " loaded for the following reason: '%(reason)s'.",
                     {'entrypoint': entrypoint,
                      'reason': exception})
        raise SystemExit(str(exception))

    def _register_mechanisms(self):
        """Register all mechanism drivers.

        This method should only be called once in the MechanismManager
        constructor.
        """
        for ext in self:
            self.mech_drivers[ext.name] = ext
            self.ordered_mech_drivers.append(ext)
        LOG.info("Registered mechanism drivers: %s",
                 [driver.name for driver in self.ordered_mech_drivers])

    def initialize(self):
        for driver in self.ordered_mech_drivers:
            LOG.info("Initializing mechanism driver '%s'", driver.name)
            driver.obj.initialize()

    def _check_vlan_transparency(self, context):
        """Helper method for checking vlan transparecncy support.

        :param context: context parameter to pass to each method call
        :raises: neutron_lib.exceptions.vlantransparent.
        VlanTransparencyDriverError if any mechanism driver doesn't
        support vlan transparency.
        """
        if context.current.get('vlan_transparent'):
            for driver in self.ordered_mech_drivers:
                if not driver.obj.check_vlan_transparency(context):
                    raise vlan_exc.VlanTransparencyDriverError()

    def _call_on_drivers(self, method_name, context,
                         continue_on_failure=False, raise_db_retriable=False):
        """Helper method for calling a method across all mechanism drivers.

        :param method_name: name of the method to call
        :param context: context parameter to pass to each method call
        :param continue_on_failure: whether or not to continue to call
        all mechanism drivers once one has raised an exception
        :param raise_db_retriable: whether or not to treat retriable db
        exception by mechanism drivers to propagate up to upper layer so
        that upper layer can handle it or error in ML2 player
        :raises: neutron.plugins.ml2.common.MechanismDriverError
        if any mechanism driver call fails. or DB retriable error when
        raise_db_retriable=False. See neutron.db.api.is_retriable for
        what db exception is retriable
        """
        errors = []
        #针对所有driver,调用指定方式method_name
        for driver in self.ordered_mech_drivers:
            try:
                getattr(driver.obj, method_name)(context)
            except Exception as e:
                if raise_db_retriable and db_api.is_retriable(e):
                    with excutils.save_and_reraise_exception():
                        LOG.debug("DB exception raised by Mechanism driver "
                                  "'%(name)s' in %(method)s",
                                  {'name': driver.name, 'method': method_name},
                                  exc_info=e)
                LOG.exception(
                    "Mechanism driver '%(name)s' failed in %(method)s",
                    {'name': driver.name, 'method': method_name}
                )
                errors.append(e)
                if not continue_on_failure:
                    break
        if errors:
            raise ml2_exc.MechanismDriverError(
                method=method_name,
                errors=errors
            )

    def create_network_precommit(self, context):
        """Notify all mechanism drivers during network creation.

        :raises: DB retriable error if create_network_precommit raises them
        See neutron.db.api.is_retriable for what db exception is retriable
        or neutron.plugins.ml2.common.MechanismDriverError
        if any mechanism driver create_network_precommit call fails.

        Called within the database transaction. If a mechanism driver
        raises an exception, then a MechanismDriverError is propagated
        to the caller, triggering a rollback. There is no guarantee
        that all mechanism drivers are called in this case.
        """
        self._check_vlan_transparency(context)
        self._call_on_drivers("create_network_precommit", context,
                              raise_db_retriable=True)

    def create_network_postcommit(self, context):
        """Notify all mechanism drivers after network creation.

        :raises: neutron.plugins.ml2.common.MechanismDriverError
        if any mechanism driver create_network_postcommit call fails.

        Called after the database transaction. If a mechanism driver
        raises an exception, then a MechanismDriverError is propagated
        to the caller, where the network will be deleted, triggering
        any required cleanup. There is no guarantee that all mechanism
        drivers are called in this case.
        """
        self._call_on_drivers("create_network_postcommit", context)

    def update_network_precommit(self, context):
        """Notify all mechanism drivers during network update.

        :raises: DB retriable error if create_network_precommit raises them
        See neutron.db.api.is_retriable for what db exception is retriable
        or neutron.plugins.ml2.common.MechanismDriverError
        if any mechanism driver update_network_precommit call fails.

        Called within the database transaction. If a mechanism driver
        raises an exception, then a MechanismDriverError is propagated
        to the caller, triggering a rollback. There is no guarantee
        that all mechanism drivers are called in this case.
        """
        self._call_on_drivers("update_network_precommit", context,
                              raise_db_retriable=True)

    def update_network_postcommit(self, context):
        """Notify all mechanism drivers after network update.

        :raises: neutron.plugins.ml2.common.MechanismDriverError
        if any mechanism driver update_network_postcommit call fails.

        Called after the database transaction. If any mechanism driver
        raises an error, then the error is logged but we continue to
        call every other mechanism driver. A MechanismDriverError is
        then reraised at the end to notify the caller of a failure.
        """
        self._call_on_drivers("update_network_postcommit", context,
                              continue_on_failure=True)

    def delete_network_precommit(self, context):
        """Notify all mechanism drivers during network deletion.

        :raises: DB retriable error if create_network_precommit raises them
        See neutron.db.api.is_retriable for what db exception is retriable
        or neutron.plugins.ml2.common.MechanismDriverError
        if any mechanism driver delete_network_precommit call fails.

        Called within the database transaction. If a mechanism driver
        raises an exception, then a MechanismDriverError is propagated
        to the caller, triggering a rollback. There is no guarantee
        that all mechanism drivers are called in this case.
        """
        self._call_on_drivers("delete_network_precommit", context,
                              raise_db_retriable=True)

    def delete_network_postcommit(self, context):
        """Notify all mechanism drivers after network deletion.

        :raises: neutron.plugins.ml2.common.MechanismDriverError
        if any mechanism driver delete_network_postcommit call fails.

        Called after the database transaction. If any mechanism driver
        raises an error, then the error is logged but we continue to
        call every other mechanism driver. A MechanismDriverError is
        then reraised at the end to notify the caller of a failure. In
        general we expect the caller to ignore the error, as the
        network resource has already been deleted from the database
        and it doesn't make sense to undo the action by recreating the
        network.
        """
        self._call_on_drivers("delete_network_postcommit", context,
                              continue_on_failure=True)

    def create_subnet_precommit(self, context):
        """Notify all mechanism drivers during subnet creation.

        :raises: DB retriable error if create_network_precommit raises them
        See neutron.db.api.is_retriable for what db exception is retriable
        or neutron.plugins.ml2.common.MechanismDriverError
        if any mechanism driver create_subnet_precommit call fails.

        Called within the database transaction. If a mechanism driver
        raises an exception, then a MechanismDriverError is propagated
        to the caller, triggering a rollback. There is no guarantee
        that all mechanism drivers are called in this case.
        """
        self._call_on_drivers("create_subnet_precommit", context,
                              raise_db_retriable=True)

    def create_subnet_postcommit(self, context):
        """Notify all mechanism drivers after subnet creation.

        :raises: neutron.plugins.ml2.common.MechanismDriverError
        if any mechanism driver create_subnet_postcommit call fails.

        Called after the database transaction. If a mechanism driver
        raises an exception, then a MechanismDriverError is propagated
        to the caller, where the subnet will be deleted, triggering
        any required cleanup. There is no guarantee that all mechanism
        drivers are called in this case.
        """
        self._call_on_drivers("create_subnet_postcommit", context)

    def update_subnet_precommit(self, context):
        """Notify all mechanism drivers during subnet update.

        :raises: DB retriable error if create_network_precommit raises them
        See neutron.db.api.is_retriable for what db exception is retriable
        or neutron.plugins.ml2.common.MechanismDriverError
        if any mechanism driver update_subnet_precommit call fails.

        Called within the database transaction. If a mechanism driver
        raises an exception, then a MechanismDriverError is propagated
        to the caller, triggering a rollback. There is no guarantee
        that all mechanism drivers are called in this case.
        """
        self._call_on_drivers("update_subnet_precommit", context,
                              raise_db_retriable=True)

    def update_subnet_postcommit(self, context):
        """Notify all mechanism drivers after subnet update.

        :raises: neutron.plugins.ml2.common.MechanismDriverError
        if any mechanism driver update_subnet_postcommit call fails.

        Called after the database transaction. If any mechanism driver
        raises an error, then the error is logged but we continue to
        call every other mechanism driver. A MechanismDriverError is
        then reraised at the end to notify the caller of a failure.
        """
        self._call_on_drivers("update_subnet_postcommit", context,
                              continue_on_failure=True)

    def delete_subnet_precommit(self, context):
        """Notify all mechanism drivers during subnet deletion.

        :raises: DB retriable error if create_network_precommit raises them
        See neutron.db.api.is_retriable for what db exception is retriable
        or neutron.plugins.ml2.common.MechanismDriverError
        if any mechanism driver delete_subnet_precommit call fails.

        Called within the database transaction. If a mechanism driver
        raises an exception, then a MechanismDriverError is propagated
        to the caller, triggering a rollback. There is no guarantee
        that all mechanism drivers are called in this case.
        """
        self._call_on_drivers("delete_subnet_precommit", context,
                              raise_db_retriable=True)

    def delete_subnet_postcommit(self, context):
        """Notify all mechanism drivers after subnet deletion.

        :raises: neutron.plugins.ml2.common.MechanismDriverError
        if any mechanism driver delete_subnet_postcommit call fails.

        Called after the database transaction. If any mechanism driver
        raises an error, then the error is logged but we continue to
        call every other mechanism driver. A MechanismDriverError is
        then reraised at the end to notify the caller of a failure. In
        general we expect the caller to ignore the error, as the
        subnet resource has already been deleted from the database
        and it doesn't make sense to undo the action by recreating the
        subnet.
        """
        self._call_on_drivers("delete_subnet_postcommit", context,
                              continue_on_failure=True)

    def create_port_precommit(self, context):
        """Notify all mechanism drivers during port creation.

        :raises: DB retriable error if create_network_precommit raises them
        See neutron.db.api.is_retriable for what db exception is retriable
        or neutron.plugins.ml2.common.MechanismDriverError
        if any mechanism driver create_port_precommit call fails.

        Called within the database transaction. If a mechanism driver
        raises an exception, then a MechanismDriverError is propagated
        to the caller, triggering a rollback. There is no guarantee
        that all mechanism drivers are called in this case.
        """
        self._call_on_drivers("create_port_precommit", context,
                              raise_db_retriable=True)

    def create_port_postcommit(self, context):
        """Notify all mechanism drivers of port creation.

        :raises: neutron.plugins.ml2.common.MechanismDriverError
        if any mechanism driver create_port_postcommit call fails.

        Called after the database transaction. Errors raised by
        mechanism drivers are left to propagate to the caller, where
        the port will be deleted, triggering any required
        cleanup. There is no guarantee that all mechanism drivers are
        called in this case.
        """
        self._call_on_drivers("create_port_postcommit", context)

    def update_port_precommit(self, context):
        """Notify all mechanism drivers during port update.

        :raises: DB retriable error if create_network_precommit raises them
        See neutron.db.api.is_retriable for what db exception is retriable
        or neutron.plugins.ml2.common.MechanismDriverError
        if any mechanism driver update_port_precommit call fails.

        Called within the database transaction. If a mechanism driver
        raises an exception, then a MechanismDriverError is propagated
        to the caller, triggering a rollback. There is no guarantee
        that all mechanism drivers are called in this case.
        """
        self._call_on_drivers("update_port_precommit", context,
                              raise_db_retriable=True)

    def update_port_postcommit(self, context):
        """Notify all mechanism drivers after port update.

        :raises: neutron.plugins.ml2.common.MechanismDriverError
        if any mechanism driver update_port_postcommit call fails.

        Called after the database transaction. If any mechanism driver
        raises an error, then the error is logged but we continue to
        call every other mechanism driver. A MechanismDriverError is
        then reraised at the end to notify the caller of a failure.
        """
        self._call_on_drivers("update_port_postcommit", context,
                              continue_on_failure=True)

    def delete_port_precommit(self, context):
        """Notify all mechanism drivers during port deletion.

        :raises:DB retriable error if create_network_precommit raises them
        See neutron.db.api.is_retriable for what db exception is retriable
        or neutron.plugins.ml2.common.MechanismDriverError
        if any mechanism driver delete_port_precommit call fails.

        Called within the database transaction. If a mechanism driver
        raises an exception, then a MechanismDriverError is propagated
        to the caller, triggering a rollback. There is no guarantee
        that all mechanism drivers are called in this case.
        """
        self._call_on_drivers("delete_port_precommit", context,
                              raise_db_retriable=True)

    def delete_port_postcommit(self, context):
        """Notify all mechanism drivers after port deletion.

        :raises: neutron.plugins.ml2.common.MechanismDriverError
        if any mechanism driver delete_port_postcommit call fails.

        Called after the database transaction. If any mechanism driver
        raises an error, then the error is logged but we continue to
        call every other mechanism driver. A MechanismDriverError is
        then reraised at the end to notify the caller of a failure. In
        general we expect the caller to ignore the error, as the
        port resource has already been deleted from the database
        and it doesn't make sense to undo the action by recreating the
        port.
        """
        self._call_on_drivers("delete_port_postcommit", context,
                              continue_on_failure=True)

    def bind_port(self, context):
        """Attempt to bind a port using registered mechanism drivers.

        :param context: PortContext instance describing the port

        Called outside any transaction to attempt to establish a port
        binding.
        """
        binding = context._binding
        LOG.debug("Attempting to bind port %(port)s on host %(host)s "
                  "for vnic_type %(vnic_type)s with profile %(profile)s",
                  {'port': context.current['id'],
                   'host': context.host,
                   'vnic_type': binding.vnic_type,
                   'profile': binding.profile})
        context._clear_binding_levels()
        if not self._bind_port_level(context, 0,
                                     context.network.network_segments):
            #绑定失败处理
            binding.vif_type = portbindings.VIF_TYPE_BINDING_FAILED
            LOG.error("Failed to bind port %(port)s on host %(host)s "
                      "for vnic_type %(vnic_type)s using segments "
                      "%(segments)s",
                      {'port': context.current['id'],
                       'host': context.host,
                       'vnic_type': binding.vnic_type,
                       'segments': context.network.network_segments})

    def _bind_port_level(self, context, level, segments_to_bind):
        binding = context._binding
        port_id = context.current['id']
        LOG.debug("Attempting to bind port %(port)s on host %(host)s "
                  "at level %(level)s using segments %(segments)s",
                  {'port': port_id,
                   'host': context.host,
                   'level': level,
                   'segments': segments_to_bind})

        if level == MAX_BINDING_LEVELS:
            #绑定次数过多
            LOG.error("Exceeded maximum binding levels attempting to bind "
                      "port %(port)s on host %(host)s",
                      {'port': context.current['id'],
                       'host': context.host})
            return False

        for driver in self.ordered_mech_drivers:
            #检查注册的机制类驱动能不能绑定
            if not self._check_driver_to_bind(driver, segments_to_bind,
                                              context._binding_levels):
                continue
            try:
                context._prepare_to_bind(segments_to_bind)
                driver.obj.bind_port(context) #驱动尝试着绑定此port
                segment = context._new_bound_segment
                if segment:
                    #_new_bound_segment有值，说明成功的实现了绑定（driver.obj.bind_port设置）
                    context._push_binding_level(
                        #添加portbindinglevel
                        models.PortBindingLevel(port_id=port_id,
                                                host=context.host,
                                                level=level,
                                                driver=driver.name,
                                                segment_id=segment))
                    next_segments = context._next_segments_to_bind
                    if next_segments:
                        #如果驱动要求继续绑定，则将level＋1并继续绑定
                        # Continue binding another level.
                        if self._bind_port_level(context, level + 1,
                                                 next_segments):
                            return True
                        else:
                            LOG.warning("Failed to bind port %(port)s on "
                                        "host %(host)s at level %(lvl)s",
                                        {'port': context.current['id'],
                                         'host': context.host,
                                         'lvl': level + 1})
                            #丢弃掉对相应驱动的binding尝试，尝试下一个驱动
                            context._pop_binding_level()
                    else:
                        # Binding complete.
                        # 绑定成功
                        LOG.debug("Bound port: %(port)s, "
                                  "host: %(host)s, "
                                  "vif_type: %(vif_type)s, "
                                  "vif_details: %(vif_details)s, "
                                  "binding_levels: %(binding_levels)s",
                                  {'port': port_id,
                                   'host': context.host,
                                   'vif_type': binding.vif_type,
                                   'vif_details': binding.vif_details,
                                   'binding_levels': context.binding_levels})
                        return True
            except Exception:
                LOG.exception("Mechanism driver %s failed in "
                              "bind_port",
                              driver.name)

    def is_host_filtering_supported(self):
        #所有driver支持过滤时返回True
        return all(driver.obj.is_host_filtering_supported()
                   for driver in self.ordered_mech_drivers)

    def filter_hosts_with_segment_access(
            self, context, segments, candidate_hosts, agent_getter):
        """Filter hosts with access to at least one segment.

        :returns: a subset of candidate_hosts.

        This method returns all hosts from candidate_hosts with access to a
        segment according to at least one driver.
        """
        candidate_hosts = set(candidate_hosts)
        if not self.host_filtering_supported:
            return candidate_hosts

        hosts_with_access = set()
        for driver in self.ordered_mech_drivers:
            hosts = driver.obj.filter_hosts_with_segment_access(
                context, segments, candidate_hosts, agent_getter)
            hosts_with_access |= hosts
            candidate_hosts -= hosts
            if not candidate_hosts:
                break
        return hosts_with_access

    def _check_driver_to_bind(self, driver, segments_to_bind, binding_levels):
        # To prevent a possible binding loop, don't try to bind with
        # this driver if the same driver has already bound at a higher
        # level to one of the segments we are currently trying to
        # bind. Note that it is OK for the same driver to bind at
        # multiple levels using different segments.
        segment_ids_to_bind = {s[api.SEGMENTATION_ID]
                               for s in segments_to_bind}
        for level in binding_levels:
            if (level.driver == driver.name and
                    level.segment_id in segment_ids_to_bind):
                LOG.debug("segment %(segment)s is already bound "
                          "by driver %(driver)s",
                          {"segment": level.segment_id,
                           "driver": level.driver})
                #如果binding_levels中已存在此绑定，则返回False
                return False
        return True

    def get_workers(self):
        #获取各驱动的workers
        workers = []
        for driver in self.ordered_mech_drivers:
            workers += driver.obj.get_workers()
        return workers


class ExtensionManager(stevedore.named.NamedExtensionManager):
    """Manage extension drivers using drivers."""
    #管理功能扩展，例如dns = neutron.plugins.ml2.extensions.dns_integration:DNSExtensionDriverML2
    def __init__(self):
        # Ordered list of extension drivers, defining
        # the order in which the drivers are called.
        self.ordered_ext_drivers = []

        LOG.info("Configured extension driver names: %s",
                 cfg.CONF.ml2.extension_drivers)
        super(ExtensionManager, self).__init__('neutron.ml2.extension_drivers',
                                               cfg.CONF.ml2.extension_drivers,
                                               invoke_on_load=True,
                                               name_order=True)
        LOG.info("Loaded extension driver names: %s", self.names())
        self._register_drivers()

    #注册扩展driver
    def _register_drivers(self):
        """Register all extension drivers.

        This method should only be called once in the ExtensionManager
        constructor.
        """
        #遍历self,取出所有ext,并将ext加入
        for ext in self:
            self.ordered_ext_drivers.append(ext)
        LOG.info("Registered extension drivers: %s",
                 [driver.name for driver in self.ordered_ext_drivers])

    def initialize(self):
        # Initialize each driver in the list.
        for driver in self.ordered_ext_drivers:
            LOG.info("Initializing extension driver '%s'", driver.name)
            driver.obj.initialize()

    def extension_aliases(self):
        exts = []
        for driver in self.ordered_ext_drivers:
            aliases = driver.obj.extension_aliases
            for alias in aliases:
                if not alias:
                    continue
                exts.append(alias)
                LOG.info("Got %(alias)s extension from driver '%(drv)s'",
                         {'alias': alias, 'drv': driver.name})
        return exts

    #针对每一个扩展驱动，调用其method_name方法
    def _call_on_ext_drivers(self, method_name, plugin_context, data, result):
        """Helper method for calling a method across all extension drivers."""
        for driver in self.ordered_ext_drivers:
            try:
                getattr(driver.obj, method_name)(plugin_context, data, result)
            except Exception:
                with excutils.save_and_reraise_exception():
                    LOG.info("Extension driver '%(name)s' failed in "
                             "%(method)s",
                             {'name': driver.name, 'method': method_name})

    def process_create_network(self, plugin_context, data, result):
        """Notify all extension drivers during network creation."""
        self._call_on_ext_drivers("process_create_network", plugin_context,
                                  data, result)

    def process_update_network(self, plugin_context, data, result):
        """Notify all extension drivers during network update."""
        self._call_on_ext_drivers("process_update_network", plugin_context,
                                  data, result)

    def process_create_subnet(self, plugin_context, data, result):
        """Notify all extension drivers during subnet creation."""
        self._call_on_ext_drivers("process_create_subnet", plugin_context,
                                  data, result)

    def process_update_subnet(self, plugin_context, data, result):
        """Notify all extension drivers during subnet update."""
        self._call_on_ext_drivers("process_update_subnet", plugin_context,
                                  data, result)

    def process_create_port(self, plugin_context, data, result):
        """Notify all extension drivers during port creation."""
        self._call_on_ext_drivers("process_create_port", plugin_context,
                                  data, result)

    def process_update_port(self, plugin_context, data, result):
        """Notify all extension drivers during port update."""
        self._call_on_ext_drivers("process_update_port", plugin_context,
                                  data, result)

    def _call_on_dict_driver(self, method_name, session, base_model, result):
        for driver in self.ordered_ext_drivers:
            try:
                getattr(driver.obj, method_name)(session, base_model, result)
            except Exception:
                LOG.exception("Extension driver '%(name)s' failed in "
                              "%(method)s",
                              {'name': driver.name, 'method': method_name})
                raise ml2_exc.ExtensionDriverError(driver=driver.name)

    def extend_network_dict(self, session, base_model, result):
        """Notify all extension drivers to extend network dictionary."""
        self._call_on_dict_driver("extend_network_dict", session, base_model,
                                  result)

    def extend_subnet_dict(self, session, base_model, result):
        """Notify all extension drivers to extend subnet dictionary."""
        self._call_on_dict_driver("extend_subnet_dict", session, base_model,
                                  result)

    def extend_port_dict(self, session, base_model, result):
        """Notify all extension drivers to extend port dictionary."""
        self._call_on_dict_driver("extend_port_dict", session, base_model,
                                  result)
