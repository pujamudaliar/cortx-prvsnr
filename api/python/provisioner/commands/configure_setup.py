#
# Copyright (c) 2020 Seagate Technology LLC and/or its Affiliates
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Affero General Public License for more details.
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
# For any questions about this software or licensing,
# please email opensource@seagate.com or cortx-questions@seagate.com.
#

import logging
import configparser
from enum import Enum
from typing import Type, List
from copy import deepcopy
from pathlib import Path

from . import CommandParserFillerMixin

from ..inputs import (
    METADATA_ARGPARSER,
    NetworkParams, NodeParams, NoParams,
    ReleaseParams, StorageEnclosureParams
)

from provisioner.commands import (
     PillarSet
)

from ..utils import run_subprocess_cmd
from ..values import UNCHANGED
from ..vendor import attr



logger = logging.getLogger(__name__)


class SetupType(Enum):
    SINGLE = "single"
    DUAL = "dual"
    GENERIC = "generic"
    THREE_NODE = "3_node"
    LDR_R1 = "LDR-R1"
    LDR_R2 = "LDR-R2"


class RunArgsConfigureSetupAttrs:
    path: str = attr.ib(
        metadata={
            METADATA_ARGPARSER: {
                'help': "config path to update pillar"
            }
        }
    )
    setup_type: str = attr.ib(
        metadata={
            METADATA_ARGPARSER: {
                'help': "the type of the setup",
                'choices': [st.value for st in SetupType]
            }
        },
        default=SetupType.SINGLE.value,
        # TODO EOS-12076 better validation
        converter=(lambda v: SetupType(v))
    )
    number_of_nodes: int = attr.ib(
        metadata={
            METADATA_ARGPARSER: {
                'help': "No of nodes in cluster"
            }
        },
        converter=int
    )


@attr.s(auto_attribs=True)
class RunArgsConfigureSetup:
    path: str = RunArgsConfigureSetupAttrs.path
    number_of_nodes: int = RunArgsConfigureSetupAttrs.number_of_nodes

    # FIXME number of nodes might be the same for different setup types
    setup_type: str = attr.ib(init=False, default=None)

    def __attrs_post_init__(self):
        pass


@attr.s(auto_attribs=True)
class NetworkParamsValidation:
    cluster_ip: str = NetworkParams.cluster_ip
    mgmt_vip: str = NetworkParams.mgmt_vip
    _optional_param = ['cluster_ip', 'mgmt_vip']

    def __attrs_post_init__(self):
        params = attr.asdict(self)
        missing_params = []
        for param, value in params.items():
            if value == UNCHANGED and param not in self._optional_param:
                missing_params.append(param)
        if len(missing_params) > 0:
            raise ValueError(f"Mandatory param missing {missing_params}")


@attr.s(auto_attribs=True)
class ReleaseParamsValidation:
    target_build: str = ReleaseParams.target_build
    _optional_param = []

    def __attrs_post_init__(self):
        params = attr.asdict(self)
        missing_params = []
        for param, value in params.items():
            if value == UNCHANGED and param not in self._optional_param:
                missing_params.append(param)
        if len(missing_params) > 0:
            raise ValueError(f"Mandatory param missing {missing_params}")


@attr.s(auto_attribs=True)
class StorageEnclosureParamsValidation:
    type: str = StorageEnclosureParams.type
    primary_ip: str = StorageEnclosureParams.primary_ip
    secondary_ip: str = StorageEnclosureParams.secondary_ip
    controller_user: str = StorageEnclosureParams.controller_user
    controller_secret: str = StorageEnclosureParams.controller_secret
    controller_type: str = StorageEnclosureParams.controller_type
    _optional_param = [
        'controller_type'
    ]

    def __attrs_post_init__(self):
        params = attr.asdict(self)
        # FIXME why we allow any params for the following types?
        types = ['JBOD', 'virtual', 'RBOD', 'other']
        if params['type'] in types:
            return
        missing_params = []
        for param, value in params.items():
            if value == UNCHANGED and param not in self._optional_param:
                missing_params.append(param)
        if len(missing_params) > 0:
            raise ValueError(f"Mandatory param missing {missing_params}")


@attr.s(auto_attribs=True)
class NodeParamsValidation:
    bmc_user: str = NodeParams.bmc_user
    bmc_secret: str = NodeParams.bmc_secret
    data_gateway: str = NodeParams.data_gateway
    data_netmask: str = NodeParams.data_netmask
    data_private_interfaces: List = NodeParams.data_private_interfaces
    data_private_ip: str = NodeParams.data_private_ip
    data_public_interfaces: List = NodeParams.data_public_interfaces
    data_public_ip: str = NodeParams.data_public_ip
    hostname: str = NodeParams.hostname
    mgmt_gateway: str = NodeParams.mgmt_gateway
    mgmt_interfaces: List = NodeParams.mgmt_interfaces
    mgmt_netmask: str = NodeParams.mgmt_netmask
    mgmt_public_ip: str = NodeParams.mgmt_public_ip
    roles: List = NodeParams.roles
    cvg: List = NodeParams.cvg

    _optional_param = [
        'data_public_ip',
        'roles',
        'data_netmask',
        'data_gateway',
        'data_private_ip',
        'mgmt_interfaces',
        'mgmt_public_ip',
        'mgmt_netmask',
        'mgmt_gateway',
        'cvg'
    ]

    def __attrs_post_init__(self):
        params = attr.asdict(self)
        
        # If storage.cvg.metadata or storage.cvg.data is specified,
        # check entry for the other.
        if params.get('cvg'):
            for data_set in params.get('cvg'):
                if (
                    params.get('cvg').get('data_devices') and
                    (
                        (not params.get('cvg').get('metadata_devices')) or
                        (params.get('cvg').get('metadata_devices') == UNCHANGED) or
                        (params.get('cvg').get('metadata_devices') == '')
                    )
                ):
                    raise ValueError(
                        "List of data devices is specified. "
                        "However, list of metadata devices is unspecified."
                    )
                elif (
                    params.get('cvg').get('metadata_devices') and
                    (
                        (not params.get('cvg').get('data_devices')) or
                        (params.get('cvg').get('data_devices') == UNCHANGED) or
                        (params.get('cvg').get('data_devices') == '')
                    )
                ):
                    raise ValueError(
                        "List of metadata devices is specified. "
                        "However, list of data devices is unspecified."
                    )

        missing_params = []
        for param, value in params.items():
            if value == UNCHANGED and param not in self._optional_param:
                missing_params.append(param)
        if len(missing_params) > 0:
            raise ValueError(f"Mandatory param missing {missing_params}")


@attr.s(auto_attribs=True)
class ConfigureSetup(CommandParserFillerMixin):
    input_type: Type[NoParams] = NoParams
    _run_args_type = RunArgsConfigureSetup

    validate_map = {
        "cluster": NetworkParamsValidation,
        "node": NodeParamsValidation,
        "storage": StorageEnclosureParamsValidation
    }

    def _parse_params(self, input):
        params = {}
        for key in input:
            logger.debug(f"Key being processed: {key}::{input[key]}")
            val = str(key).split(".")

            if len(val) > 1:
                logger.debug(f"Params with '.' separation: {params}")
                if val[-1] in [
                    'ip', 'user', 'secret', 'type', 'interfaces',
                    'private_interfaces', 'public_interfaces',
                    'gateway', 'netmask', 'public_ip', 'private_ip'
                ]:
                    # Node specific '.' separated params
                    # The '.' get replaced with '_'
                    params[f'{val[-2]}_{val[-1]}'] = input[key]
                    logger.debug(f"Params generated with '_': {params}")
                elif val[-3] in [
                    'cvg'
                ]:
                    if not (type(params[val[-3]]) is list):
                        params[val[-3]] = []
                    params[val[-3]][val[-2]][val[-1]] = input[key]
                    logger.debug(f"Params CVG list created: {params}")
            else:
                params[val[-1]] = input[key]
                logger.debug(f"Params with no '.' separation: \n"
                    f"{params[val[-1]]} = {input[key]}"
                )

        return params

    def _validate_params(self, input_type, content):
        params = self._parse_params(content)
        self.validate_map[input_type](**params)

    def _parse_input(self, input):
        for key in input:
            if input.get(key) and "," in input[key]:
                value = [f'\"{x.strip()}\"' for x in input[key].split(",")]
                value = ','.join(value)
                input[key] = f'[{value}]'
            elif (
                'interfaces' in key or
                'roles' in key or
                'cvg' in key
            ):
                # special case single value as array
                # Need to fix this array having single value
                input[key] = f'[\"{input[key]}\"]'
            else:
                if input.get(key):
                    if input[key] == 'None':
                        input[key] = '\"\"'
                    else:
                        input[key] = f'\"{input[key]}\"'
                else:
                    input[key] = UNCHANGED

        # Special treatment for srvnode_storage



    def _parse_pillar_key(self, key):
        pillar_key = deepcopy(key)
        return pillar_key.replace(".", "/")

    def run(self, path, number_of_nodes):  # noqa: C901

        if not Path(path).is_file():
            raise ValueError('config file is missing')

        config = configparser.ConfigParser()
        config.read(path)
        logger.info("Updating salt data")
        content = {section: dict(config.items(section)) for section in config.sections()}  # noqa: E501
        logger.debug(f"Data from config.ini: \n{content}")

        input_type = None
        pillar_type = None
        node_list = []
        count = int(number_of_nodes)

        # Process server_default section
        # copy data from server_default to individual server_node sections
        # delete server_default section
        server_default = content["server_default"]
        enclosure_default = content["enclosure_default"]
        del content["server_default"]
        del content["enclosure_default"]

        for section in content.keys():
            if 'srvnode' in section:
                tmp_section = server_default
                tmp_section.update(content[section])
            elif 'enclosure' in section:
                tmp_section = enclosure_default
                tmp_section.update(content[section])
            
            content[section] = tmp_section
            tmp_section = {}
            logger.debug(f"Content {section}::{content[section]}")

        logger.debug(f"Segregated sections: \n{content}")

        for section in content:
            if 'srvnode' in section:
                input_type = 'node'
                pillar_type = f'cluster/{section}'
                count = count - 1
                node_list.append(f"\"{section}\"")
            elif 'enclosure' in section:
                input_type = 'storage'
                pillar_type = f'storage/{section}'
                count = count - 1
                node_list.append(f"\"{section}\"")

            self._validate_params(input_type, content[section])
            self._parse_input(content[section])

            for pillar_key in content[section]:
                if 'storage' in pillar_key:
                    PillarSet().run(content[section])
                else:
                    key = f'{pillar_type}/{self._parse_pillar_key(pillar_key)}'
                    PillarSet().run(content[section])
                    # run_subprocess_cmd([
                    #         "provisioner", "pillar_set",
                    #         key, f"{content[section][pillar_key]}"])

        if count > 0:
            raise ValueError(f"Node information for {count} node missing")

        logger.info("Pillar data updated Successfully.")
