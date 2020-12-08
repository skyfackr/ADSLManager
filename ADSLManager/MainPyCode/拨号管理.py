#__all__=[]
def DONOTIMPORT():
    print('请直接运行此代码而非引用')
    raise ImportError
__import__=DONOTIMPORT()
DEFAULT_CONFIG_DIR='./ADSLManager.ini'
import os,time,base64,configparser,string,logging,sys,uuid
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
class ADSLManagerBaseDIYException(Exception):
    pass


class ADSLClass(object):
    class ADSLErrors(ADSLManagerBaseDIYException):
        pass
    class PasswordVerifyFailedException(ADSLErrors):
        pass
    class AttributeErrorException(ADSLErrors):
        pass
    class ConfigDamagedException(ADSLErrors):
        pass
    class ConfigInvaildSchemaException(ADSLErrors):
        pass

    def __init__(self,name:str=None,account:str=None,password:str=None,order:str=None,config:str=None):
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

    def setPassword(self,password:str,order:str):
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
    
    def calHash(self,originPw:str):
        return SHA256.new(str({
            'name':self.getName(),
            'account':self.getAccount(),
            'password':originPw}).encode()).hexdigest()

    def setHash(self,originPw:str):
        self.accountHash=self.calHash(originPw)
        return

    def getPassword(self,order:str):
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

    def callInternet(self,order:str):
        #pw=self.getPassword(order)
        return os.system('rasdial {} {} {}'.format(self.getName(),self.getAccount(),self.getPassword(order)))

    def disconnect(self):
        return os.system('rasdial {} /disconnect'.format(self.getName()))

    @classmethod
    def status(self):
        return os.system('rasdial')

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


global ADSLObject,logger
ADSLObject=[]
logger=logging.getLogger()

class cmdUI(object):
    class errors(object):
        class ADSLManagerBaseErrors(ADSLManagerBaseDIYException):
            pass
        class SystemInteralError(ADSLManagerBaseErrors):
            def __init__(self,e:Exception):
                id=str(uuid.uuid1())
                logger.error('Interal Errors Found UUID:{}'.format(id),exc_info=e)
                print(cmdUI.UISpiltLineFormat('''
                出现内部错误，请根据UUID以及日志查错
                UUID:{}
                '''.format(id)))
                return

            class SystemInteralErrorFlag(ADSLManagerBaseErrors):
                pass

            @classmethod
            def new(cls,msg:str=None):
                return cls(cls.SystemInteralErrorFlag(msg))
        class UserError(ADSLManagerBaseErrors):
            def __init__(self,e:Exception):
                id=str(uuid.uuid1())
                logger.error('User Caused Errors Found UUID:{}'.format(id),exc_info=e)
                print(cmdUI.UISpiltLineFormat('''
                用户输入信息有误，请根据UUID以及日志查错
                UUID:{}
                错误简报：{}
                '''.format(id,repr(e))))
                return
            class UserErrorFlag(ADSLManagerBaseErrors):
                pass

            @classmethod
            def new(cls,msg:str=None):
                return cls(cls.UserErrorFlag(msg))

    def __init__(self):
        self.nowConfigFile=None


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

    def getKeyCode(self,c:str):
        if c==None:
            return None
        if type(c)!=str or len(c)!=1:
            raise self.errors.SystemInteralError.new('this func can only accept ONE CHAR')
        return keyboard.KeyCode.from_char(c)

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
        self.clear()
        print('正在尝试加载：{}'.format(dir))
        logger.info('try load config:{}'.format(dir))
        time.sleep(1000)
        try:
            ADSLObject+=ADSLClass.patchLoad(dir)
        except ADSLClass.ADSLErrors as e:
            raise self.errors.UserError(e)
        except Exception as e:
            raise self.errors.SystemInteralError(e)
        print('\n加载成功')
        self.nowConfigFile=dir
        time.sleep(2000)
        self.menuAfterLoad()


    def createConf(self):
        ans_config=configparser.ConfigParser()
        ans_config['ADSLManager']={
            'version':'1.0.0',
            'config_sum':0}
        with open(DEFAULT_CONFIG_DIR,'w+') as f:
            ans_config.write(f)
            logger.info('create default config')
            print('创建初始文件成功')
        return

    def mainMenu(self):
        self.clear()
        if os.path.isfile(DEFAULT_CONFIG_DIR):
            if os.path.exists(DEFAULT_CONFIG_DIR):
                logger.info('found one exist default data')
                print('''发现一个配置文件。是否需要加载？
                文件路径:{}
                按y开始加载'''.format(os.path.abspath(DEFAULT_CONFIG_DIR)))
                key=self.waitPress()
                if key==self.getKeyCode('c') or key==self.getKeyCode('C'):
                    self.loadConf(DEFAULT_CONFIG_DIR)
                    return
        self.clear()
        print('''
        1.选择配置文件
        2.查询当前状态
        3.创建新的配置文件
        4.退出
        ''')
        while True:
            nowkey=self.waitPress()
            if nowkey==self.getKeyCode('1'):
                self.clear()
                print('请输入路径：')
                input(input_dir)
                if not (os.path.isfile(input_dir) and os.path.exists(input_dir)):
                    print('没有找到该文件，请重试')
                    continue
                self.loadConf(input_dir)
                return
            if nowkey==self.getKeyCode('2'):
                ADSLClass.status()
                continue
            if nowkey==self.getKeyCode('4'):
                self.clear()
                print('感谢使用')
                logger.info('exit by user')
                exit(0)
            if nowkey==self.getKeyCode('3'):
                try:
                    self.createConf()
                except Exception as e:
                    raise self.errors.SystemInteralError(e)
                continue
    
    @classmethod
    def UISpiltLineFormat(cls,origin_str:str,line_char:str='-'):
        if line_char==None or line_char=='':
            return origin_str
        if not len(line_char)==1:
            raise cls.errors.SystemInteralError.new('the attribute line_char can only accept one char')
        lineList=origin_str.splitlines(False)
        lineNum=-1
        for thisline in lineList:
            lineNum=max(lineNum,len(thisline))
        return line_char*lineNum+'\n'+origin_str+'\n'+line_char*lineNum+'\n'


    def menuAfterLoad(self):
        self.clear()
        print(self.UISpiltLineFormat('''
        加载文件信息：
        文件名：{} 存档版本号：就没更新过有个锤子用 总文件数：{}
        '''.format(self.nowConfigFile,len(ADSLObject))))
        print('按下一个按钮执行操作')
        liststr=None
        for now in ADSLObject:
            liststr+=now.getName()+'\n'
        print(self.UISpiltLineFormat('''

        {}
        
        0.断开连接
        1-x.启动对应链接
        U.查询当前状态
        X.退出程序
        S.保存当前配置文件
        A.添加一个链接配置
        D.删除一个连接配置
        '''.format(self.UISpiltLineFormat(liststr or '没有找到啥链接。请添加几个','#')),'*'))
        nowkey=self.waitPress()
