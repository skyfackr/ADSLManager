#__all__=[]
def DONOTIMPORT():
    print('请直接运行此代码而非引用')
    raise ImportError
__import__=DONOTIMPORT()
DEFAULT_CONFIG_DIR='./ADSLManager.ini'
import os,time,base64,configparser
from pynput import *
from Cryptodome.Cipher import *
from Cryptodome.Hash import *
from datetime import datetime
'''
;example config schema
[ADSLManager]
version=1.0.0
config_sum=x
;x为配置文件总数

[ADSLConfigX]
;X为从1开始往后延的数字，每一节代表一份配置，一共有config_sum节
name=123456
account=123456
encPw=xxxxxx
;加密的密码
hash=xxx
'''
class ADSLClass(object):
    class ADSLErrors(Exception):
        pass
    class PasswordVerifyFailedException(ADSLErrors):
        pass
    class AttributeErrorException(ADSLErrors):
        pass
    class ConfigDamagedException(ADSLErrors):
        pass
    class ConfigInvaildSchemaException(ADSLErrors):
        pass

    def __init__(self,name:string=None,account:string=None,password:string=None,order:string=None,config:string=None):
        if config!=None:
            self.load(config)
            return
        if name==None or account==None or password==None or order==None:
            raise AttributeErrorException
        self.name=name
        self.ac=account
        self.encPw=None
        self.accountHash=None
        self.setPassword(password,order)
        #self.errors=Errors()

    def setPassword(self,password:string,order:string):
        self.setHash(password)
        AESsk=SHA256.new(order.encode())[:31]
        password=password.encode()
        padCode=len(password)%AES.block_size
        if padCode==0:
            padCode=AES.block_size
        password+=chr(padCode)*padCode
        ansPw=base64.b64encode(AES.new(AESsk).encrypt(password))
        self.encPw=ansPw
        return

    #@properly
    def getName(self):
        return self.name

    def getEncryptedPassword(self):
        return self.encPw

    def getAccount(self):
        return self.ac

    def getHash(self):
        return self.accountHash
    
    def calHash(self,originPw:string):
        return SHA256.new(string({
            'name':self.getName(),
            'account':self.getAccount(),
            'password':originPw}).encode()).hexdigest()

    def setHash(self,originPw:string):
        self.accountHash=self.calHash(originPw)
        return

    def getPassword(self,order:string):
        AESsk=SHA256.new(order.encode())[:31]
        try:
            ansPw=AES.new(AESsk).decrypt(base64.b64decode(self.encPw))
            padCode=ansPw[-1]
            ansPw=ansPw[:len(ansPw)-ord(padCode)].decode()
        except Exception:
            raise PasswordVerifyFailedException
        if self.getHash()!=self.calHash(ansPw):
            raise PasswordVerifyFailedException
        return ansPw

    def callInternet(self,order:string):
        #pw=self.getPassword(order)
        return os.system('rasdial {} {} {}'.format(self.getName(),self.getAccount(),self.getPassword(order)))

    def disconnect(self):
        return os.system('rasdial {} /disconnect'.format(self.getName()))

    @classmethod
    def save(cls,save_list:list,save_dir):
        if not os.path.isfile(save_dir):
            raise AttributeErrorException
        ans_config=configparser.ConfigParser()
        ans_config['ADSLManager']={
            'version':'1.0.0',
            'config_sum':0}
        for deal in save_list:
            if type(deal)!=ADSLClass:
                raise AttributeErrorException
            ans_config['ADSLManager']['config_sum']+=1
            ans_config['ADSLConfig{}'.format(ans_config['ADSLManager']['config_sum'])]={
                'name':deal.getName(),
                'account':deal.getAccount(),
                'encPw':deal.getEncryptedPassword(),
                'hash':deal.getHash()}
        with (open(save_dir,'w')) as f:
            ans_config.write(f)
        return



    def load(self,config):
        nameNeeded=['name','account','encPw','hash']
        for tested in nameNeeded:
            if not tested in config.keys():
                raise ConfigInvaildSchemaException
        self.name=config['name']
        self.ac=config['account']
        self.encPw=config['encPw']
        self.accountHash=config['hash']
        return

    @classmethod
    def patchLoad(cls,config_dir):
        if not os.path.isfile(config_dir):
            raise AttributeErrorException
        try:
            config_data=configparser.ConfigParser()
            config_data.read(config_dir)
        except Exception:
            raise ConfigDamagedException
        try:
            config={}
            loaded=[]
            config['total']={}
            config['total']['ver']=config_data.get('ADSLManager','version')
            config['total']['len']=config_data.get('ADSLManager','config_sum')
            for i in range(config['total']['len']):
                preLoadSection=config['ADSLConfig{}'.format(i+1)]
                load_data={
                    'name':preLoadSection['name'],
                    'account':preLoadSection['account'],
                    'encPw':preLoadSection['encPw'],
                    'hash':preLoadSection['hash']}
                loaded.append(ADSLClass(config=load_data))
        except Exception:
            raise ConfigInvaildSchemaException
        return loaded
if not __name__=='__main__':
    print('请直接运行此代码而非引用')
    exit(1)


global ADSLObject
ADSLObject=[]

class cmdUI(object):
    def clear(self):
        os.system('cls')

    def waitPress(self):
        key=None
        def onPress(nowkey):
            key=nowkey
        def onFin(*args):
            return False
        with keyboard.Listener(on_press=onPress,on_release=onFin) as listener:
            listener.join()
        return key

    def index(self):
        self.clear()
        print('''拨号管理系统
        powered by skyfackr
        licensed in GPLv3

        点按任意键继续
        ''')
        self.waitPress()
        return None

    def loadConf(self,dir):
        pass

    def mainMenu(self):
        if os.path.isfile(DEFAULT_CONFIG_DIR):
            if os.path.exists(DEFAULT_CONFIG_DIR):
                print('''发现一个配置文件。是否需要加载？
                文件路径:{}
                按y开始加载'''.format(os.path.abspath(DEFAULT_CONFIG_DIR)))
                key=self.waitPress()

