# Copyright (c) 2014 OpenStack Foundation
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

import collections
import itertools
import uuid

from oslo_log import log as logging
from oslo_serialization import jsonutils
from oslo_utils import excutils
from oslo_utils import uuidutils
from ovsdbapp import api as ovsdb_api
import six

from neutron.agent.common import utils
from neutron.agent.ovsdb import api as ovsdb

LOG = logging.getLogger(__name__)


def api_factory(context):
    return OvsdbVsctl(context)


class Transaction(ovsdb_api.Transaction):
    def __init__(self, context, check_error=False, log_errors=True, opts=None):
        self.context = context
        self.check_error = check_error
        self.log_errors = log_errors
        self.opts = ["--timeout=%d" % self.context.vsctl_timeout,
                     '--oneline', '--format=json']
        if opts:
            self.opts += opts
        self.commands = []

    #添加命令
    def add(self, command):
        self.commands.append(command)
        return command

    #提交所有命令
    def commit(self):
        args = []
        for cmd in self.commands:
            cmd.result = None
            args += cmd.vsctl_args()
        # 执行命令
        res = self.run_vsctl(args)
        if res is None:
            #无输出
            return
        res = res.replace(r'\\', '\\').splitlines()
        #构造每个命令的输出
        for i, record in enumerate(res):
            self.commands[i].result = record
        #返回每个命令的输出
        return [cmd.result for cmd in self.commands]

    #执行ovs-vsctl命令,返回输出
    def run_vsctl(self, args):
        full_args = ["ovs-vsctl"] + self.opts + args
        try:
            # We log our own errors, so never have utils.execute do it
            return utils.execute(full_args, run_as_root=True,
                                 log_fail_as_error=False).rstrip()
        except Exception as e:
            with excutils.save_and_reraise_exception() as ctxt:
                if self.log_errors:
                    LOG.error("Unable to execute %(cmd)s. "
                              "Exception: %(exception)s",
                              {'cmd': full_args, 'exception': e})
                if not self.check_error:
                    ctxt.reraise = False


class BaseCommand(ovsdb_api.Command):
    def __init__(self, context, cmd, opts=None, args=None):
        self.context = context
        self.cmd = cmd
        self.opts = [] if opts is None else opts
        self.args = [] if args is None else args

    #按事务执行命令
    def execute(self, check_error=False, log_errors=True):
        with Transaction(self.context, check_error=check_error,
                         log_errors=log_errors) as txn:
            txn.add(self)
        return self.result

    def vsctl_args(self):
        return itertools.chain(('--',), self.opts, (self.cmd,), self.args)


class MultiLineCommand(BaseCommand):
    """Command for ovs-vsctl commands that return multiple lines"""
    @property
    def result(self):
        return self._result

    @result.setter
    def result(self, raw_result):
        self._result = raw_result.split(r'\n') if raw_result else []


class DbCommand(BaseCommand):
    def __init__(self, context, cmd, opts=None, args=None, columns=None):
        if opts is None:
            opts = []
        if columns:
            opts += ['--columns=%s' % ",".join(columns)]
        super(DbCommand, self).__init__(context, cmd, opts, args)

    @property
    def result(self):
        return self._result

    @result.setter
    def result(self, raw_result):
        # If check_error=False, run_vsctl can return None
        if not raw_result:
            self._result = None
            return

        try:
            json = jsonutils.loads(raw_result)
        except (ValueError, TypeError) as e:
            # This shouldn't happen, but if it does and we check_errors
            # log and raise.
            with excutils.save_and_reraise_exception():
                LOG.error("Could not parse: %(raw_result)s. "
                          "Exception: %(exception)s",
                          {'raw_result': raw_result, 'exception': e})

        headings = json['headings']
        data = json['data']
        results = []
        for record in data:
            obj = {}
            for pos, heading in enumerate(headings):
                obj[heading] = ovsdb.val_to_py(record[pos])
            results.append(obj)
        self._result = results


class DbGetCommand(DbCommand):
    @DbCommand.result.setter
    def result(self, val):
        # super()'s never worked for setters http://bugs.python.org/issue14965
        DbCommand.result.fset(self, val)
        # DbCommand will return [{'column': value}] and we just want value.
        if self._result:
            self._result = list(self._result[0].values())[0]


class DbCreateCommand(BaseCommand):
    def __init__(self, context, opts=None, args=None):
        super(DbCreateCommand, self).__init__(context, "create", opts, args)
        # NOTE(twilson) pre-commit result used for intra-transaction reference
        self.record_id = "@%s" % uuidutils.generate_uuid()
        self.opts.append("--id=%s" % self.record_id)

    @property
    def result(self):
        return self._result

    @result.setter
    def result(self, val):
        self._result = uuid.UUID(val) if val else val


class BrExistsCommand(DbCommand):
    @DbCommand.result.setter
    def result(self, val):
        self._result = val is not None

    def execute(self):
        return super(BrExistsCommand, self).execute(check_error=False,
                                                    log_errors=False)


#ovsdb控制
class OvsdbVsctl(ovsdb_api.API):
    def __init__(self, context):
        super(OvsdbVsctl, self).__init__()
        self.context = context

    def create_transaction(self, check_error=False, log_errors=True, **kwargs):
        return Transaction(self.context, check_error, log_errors, **kwargs)

    def add_manager(self, connection_uri):
        # This will add a new manager without overriding existing ones.
        conn_uri = 'target="%s"' % connection_uri
        args = ['create', 'Manager', conn_uri, '--', 'add', 'Open_vSwitch',
                '.', 'manager_options', '@manager']
        return BaseCommand(self.context, '--id=@manager', args=args)

    def get_manager(self):
        return MultiLineCommand(self.context, 'get-manager')

    def remove_manager(self, connection_uri):
        args = ['get', 'Manager', connection_uri, '--', 'remove',
                'Open_vSwitch', '.', 'manager_options', '@manager']
        return BaseCommand(self.context, '--id=@manager', args=args)

    #添加br
    def add_br(self, name, may_exist=True, datapath_type=None):
        opts = ['--may-exist'] if may_exist else None
        params = [name]
        if datapath_type:
            params += ['--', 'set', 'Bridge', name,
                       'datapath_type=%s' % datapath_type]
        return BaseCommand(self.context, 'add-br', opts, params)

    #删除br
    def del_br(self, name, if_exists=True):
        opts = ['--if-exists'] if if_exists else None
        return BaseCommand(self.context, 'del-br', opts, [name])

    #检查br是否存在（通过执行list　$br-name命令）
    def br_exists(self, name):
        return BrExistsCommand(self.context, 'list', args=['Bridge', name])

    def port_to_br(self, name):
        return BaseCommand(self.context, 'port-to-br', args=[name])

    def iface_to_br(self, name):
        return BaseCommand(self.context, 'iface-to-br', args=[name])

    def list_br(self):
        return MultiLineCommand(self.context, 'list-br')

    def br_get_external_id(self, name, field):
        return BaseCommand(self.context, 'br-get-external-id',
                           args=[name, field])

    def db_create(self, table, **col_values):
        args = [table]
        args += _set_colval_args(*col_values.items())
        return DbCreateCommand(self.context, args=args)

    def db_destroy(self, table, record):
        args = [table, record]
        return BaseCommand(self.context, 'destroy', args=args)

    def db_set(self, table, record, *col_values):
        args = [table, record]
        args += _set_colval_args(*col_values)
        return BaseCommand(self.context, 'set', args=args)

    def db_add(self, table, record, column, *values):
        args = [table, record, column]
        for value in values:
            if isinstance(value, collections.Mapping):
                args += ["{}={}".format(ovsdb.py_to_val(k), ovsdb.py_to_val(v))
                         for k, v in value.items()]
            else:
                args.append(ovsdb.py_to_val(value))
        return BaseCommand(self.context, 'add', args=args)

    def db_clear(self, table, record, column):
        return BaseCommand(self.context, 'clear', args=[table, record,
                                                        column])

    def db_get(self, table, record, column):
        # Use the 'list' command as it can return json and 'get' cannot so that
        # we can get real return types instead of treating everything as string
        # NOTE: openvswitch can return a single atomic value for fields that
        # are sets, but only have one value. This makes directly iterating over
        # the result of a db_get() call unsafe.
        return DbGetCommand(self.context, 'list', args=[table, record],
                            columns=[column])

    def db_list(self, table, records=None, columns=None, if_exists=False):
        opts = ['--if-exists'] if if_exists else None
        args = [table]
        if records:
            args += records
        return DbCommand(self.context, 'list', opts=opts, args=args,
                         columns=columns)

    def db_find(self, table, *conditions, **kwargs):
        columns = kwargs.pop('columns', None)
        args = itertools.chain([table],
                               *[_set_colval_args(c) for c in conditions])
        return DbCommand(self.context, 'find', args=args, columns=columns)

    def set_controller(self, bridge, controllers):
        return BaseCommand(self.context, 'set-controller',
                           args=[bridge] + list(controllers))

    #删除掉controller
    def del_controller(self, bridge):
        return BaseCommand(self.context, 'del-controller', args=[bridge])

    def get_controller(self, bridge):
        return MultiLineCommand(self.context, 'get-controller', args=[bridge])

    #设置失效模式
    def set_fail_mode(self, bridge, mode):
        return BaseCommand(self.context, 'set-fail-mode', args=[bridge, mode])

    def add_port(self, bridge, port, may_exist=True):
        opts = ['--may-exist'] if may_exist else None
        return BaseCommand(self.context, 'add-port', opts, [bridge, port])

    def del_port(self, port, bridge=None, if_exists=True):
        opts = ['--if-exists'] if if_exists else None
        args = filter(None, [bridge, port])
        return BaseCommand(self.context, 'del-port', opts, args)

    def list_ports(self, bridge):
        return MultiLineCommand(self.context, 'list-ports', args=[bridge])

    def list_ifaces(self, bridge):
        return MultiLineCommand(self.context, 'list-ifaces', args=[bridge])

    def db_remove(self, table, record, column, *values, **keyvalues):
        raise NotImplementedError()

    def db_find_rows(self, table, *conditions, **kwargs):
        raise NotImplementedError()

    def db_list_rows(self, table, record=None, if_exists=False):
        raise NotImplementedError()


def _set_colval_args(*col_values):
    args = []
    # TODO(twilson) This is ugly, but set/find args are very similar except for
    # op. Will try to find a better way to default this op to '='
    for entry in col_values:
        if len(entry) == 2:
            col, op, val = entry[0], '=', entry[1]
        else:
            col, op, val = entry
        if isinstance(val, collections.Mapping):
            args += ["%s:%s%s%s" % (
                col, k, op, ovsdb.py_to_val(v)) for k, v in val.items()]
        elif (isinstance(val, collections.Sequence)
                and not isinstance(val, six.string_types)):
            if len(val) == 0:
                args.append("%s%s%s" % (col, op, "[]"))
            else:
                args.append(
                    "%s%s%s" % (col, op, ",".join(map(ovsdb.py_to_val, val))))
        else:
            args.append("%s%s%s" % (col, op, ovsdb.py_to_val(val)))
    return args
