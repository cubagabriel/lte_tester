"""
Copyright 2020 The Magma Authors.

This source code is licensed under the BSD-style license found in the
LICENSE file in the root directory of this source tree.

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""


import abc
import subprocess


KEY = '000102030405060708090A0B0C0D0E0F'
#OP='11111111111111111111111111111111' -> OPc='24c05f7c2f2b368de10f252f25f6cfc2'
OPC = '24c05f7c2f2b368de10f252f25f6cfc2'
RETRY_COUNT = 4
RETRY_INTERVAL = 1  # seconds


class S1apTimeoutError(Exception):
    """ Indicate that a test-related check has timed out. """
    pass


class SubscriberDbClient(metaclass=abc.ABCMeta):
    """ Interface for the Subscriber DB. """

    @abc.abstractmethod
    def add_subscriber(self, sid):
        """
        Add a subscriber to the EPC by :sid:.
        Args:
            sid (str): the SID to add
        """
        raise NotImplementedError()

    @abc.abstractmethod
    def delete_subscriber(self, sid):
        """
        Delete a subscriber from the EPC by :sid:.
        Args:
            sid (str): the SID to delete
        """
        raise NotImplementedError()

    @abc.abstractmethod
    def list_subscriber_sids(self):
        """
        List all stored subscribers. Is blocking.
        Returns:
            sids (str[]): list of subscriber SIDs
        """
        raise NotImplementedError()

    @abc.abstractmethod
    def clean_up(self):
        """ Clean up, delete all subscribers. """
        raise NotImplementedError()

    @abc.abstractmethod
    def wait_for_changes(self):
        """
        Blocks until changes go through. This is really only implemented on
        the cloud side, where subscriber changes can take a while to propagate
        from cloud to gateway
        """
        raise NotImplementedError()


class SubscriberDbCassandra(SubscriberDbClient):
    """
    Handle subscriber action by making calls to Cassandra database of OAI HSS
    """
    HSS_IP = '10.128.0.2'
    HSS_USER = 'cuba_gabriel'
    IDENTITY_FILE = '$HOME/.ssh/id_rsa'
    CASSANDRA_SERVER_IP = '10.128.0.2'
    MME_IDENTITY = 'mme.openair4G.eur'

    def __init__(self):
        self._added_sids = set()
        print("*********Init SubscriberDbCassandra***********")
        add_mme_cmd = "$HOME/openair-hss/scripts/data_provisioning_mme --id 2 "\
            "--mme-identity " + self.MME_IDENTITY + " --realm openair4G.eur "\
            "--ue-reachability 1 -C "+ self.CASSANDRA_SERVER_IP
        self._run_remote_cmd(add_mme_cmd)

    def _run_remote_cmd(self, cmd_str):
        ssh_args = "-o UserKnownHostsFile=/dev/null "\
            "-o StrictHostKeyChecking=no"
        ssh_cmd = "ssh -i {id_file} {args} {user}@{host} {cmd}".format(
            id_file=self.IDENTITY_FILE, args=ssh_args, user=self.HSS_USER,
            host=self.HSS_IP, cmd=cmd_str)
        output, error = subprocess.Popen(ssh_cmd, shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE).communicate()
        print("Output: ", output)
        print("Error: ", error)
        return output, error

    def add_subscriber(self, sid):
        sid = sid[4:]
        print("Adding subscriber", sid)
        # Insert into users
        add_usr_cmd = "$HOME/openair-hss/scripts/data_provisioning_users "\
            "--apn magma.ipv4 --apn2 internet --key " + KEY + \
            " --imsi-first " + sid + " --mme-identity "+ self.MME_IDENTITY +\
            " --no-of-users 1 --realm openair4G.eur --opc "+ OPC + \
            " --cassandra-cluster " + self.CASSANDRA_SERVER_IP
        self._run_remote_cmd(add_usr_cmd)

    def delete_subscriber(self, sid):
        print("Removing single subscriber not supported")

    def _delete_all_subscribers(self):
        print("Removing all subscribers")
        del_all_subs_cmd = "$HOME/openair-hss/scripts/data_provisioning_users "\
            "--verbose True --truncate True -n 0 "\
            "-C " + self.CASSANDRA_SERVER_IP
        self._run_remote_cmd(del_all_subs_cmd)

    def list_subscriber_sids(self):
        sids = []
        return sids

    def clean_up(self):
        self._delete_all_subscribers()

    def wait_for_changes(self):
        # On gateway, changes propagate immediately
        return
