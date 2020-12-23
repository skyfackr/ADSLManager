import base64
import configparser
import logging
import os
import sys
import threading
import time
import uuid

from Cryptodome.Cipher import AES
from Cryptodome.Hash import SHA256
from pynput import *

DEBUGMODE = True
LOGFILE = './adslmanager.log'


def DONOTIMPORT():
    if not __name__ == '__main__':
        print('请直接运行此代码而非引用')
        raise ImportError('you have no access to import this module from other code.please run it at command')


__import__ = DONOTIMPORT()
DEFAULT_CONFIG_DIR = './ADSLManager.ini'
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
global ADSLManagerBaseDIYException


def exit(code):
    logger.debug('exit flag 0')
    if DEBUGMODE:
        logger.debug('exit flag 1')
        callCmd('pause')
        logger.debug('exit flag 1.5')
    logger.debug('exit flag 2')
    sys.exit(code)


# noinspection PyRedeclaration
class ADSLManagerBaseDIYException(Exception):
    pass


def callCmd(cmd: str):
    print(os.popen(cmd).read())
    return


# noinspection PyUnresolvedReferences,PyProtectedMember
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

    def __init__(self, name: str = None, account: str = None, password: str = None, order: str = None,
                 config: [dict, None] = None):
        if config is not None:
            self.load(config)
            return
        if name is None or account is None or password is None or order is None:
            raise self.AttributeErrorException
        self.name = str(name)
        self.ac = str(account)
        password = str(password)
        order = str(order)
        self.encPw = None
        self.accountHash = None
        self.setPassword(password, order)
        # self.errors=Errors()

    def setPassword(self, password: str, order: str):
        self.setHash(password)
        AESsk = SHA256.new(order.encode()).hexdigest()[:32].encode()
        password = password.encode()
        from Cryptodome.Cipher import AES
        padCode = len(password) % AES.block_size
        if padCode == 0:
            padCode = AES.block_size
        password += (chr(padCode) * padCode).encode()
        ansPw = base64.b64encode(AES.new(AESsk, AES.MODE_EAX).encrypt(password))
        self.encPw = ansPw
        return

    # @properly
    def getName(self):
        return self.name

    def getEncryptedPassword(self):
        return self.encPw

    def getAccount(self):
        return self.ac

    def getHash(self):
        return self.accountHash

    def calHash(self, originPw: str):
        return SHA256.new(str({
            'name': self.getName(),
            'account': self.getAccount(),
            'password': originPw}).encode()).hexdigest()

    def setHash(self, originPw: str):
        self.accountHash = self.calHash(originPw)
        return

    def getPassword(self, order: str):
        AESsk = SHA256.new(order.encode()).hexdigest()[:32].encode()
        try:
            ansPw = AES.new(AESsk, AES.MODE_EAX).decrypt(base64.b64decode(self.encPw))
            padCode = ansPw[-1].decode()
            ansPw = ansPw[:len(ansPw) - ord(padCode)].decode()
        except Exception:
            raise self.PasswordVerifyFailedException
        if self.getHash() != self.calHash(ansPw):
            raise self.PasswordVerifyFailedException
        return ansPw

    def callInternet(self, order: str):
        # pw=self.getPassword(order)
        return callCmd('rasdial {} {} {}'.format(self.getName(), self.getAccount(), self.getPassword(order)))

    def disconnect(self):
        return callCmd('rasdial {} /disconnect'.format(self.getName()))

    @classmethod
    def status(cls):
        return callCmd('rasdial')

    @classmethod
    def save(cls, save_list: list, save_dir):
        if not os.path.isfile(save_dir):
            raise cls.AttributeErrorException
        ans_config = configparser.ConfigParser()
        ans_config['ADSLManager'] = {
            'version': '1.0.0',
            'config_sum': 0}
        for deal in save_list:
            if type(deal) != ADSLClass:
                raise cls.AttributeErrorException
            ans_config['ADSLManager']['config_sum'] = str(int(ans_config['ADSLManager']['config_sum']) + 1)
            ans_config['ADSLConfig{}'.format(ans_config['ADSLManager']['config_sum'])] = {
                'name': deal.getName(),
                'account': deal.getAccount(),
                'encPw': deal.getEncryptedPassword(),
                'hash': deal.getHash()}
        with (open(save_dir, 'w')) as f:
            ans_config.write(f)
        return

    def load(self, config: dict):
        nameNeeded = ['name', 'account', 'encPw', 'hash']
        for tested in nameNeeded:
            if tested not in config.keys():
                raise self.ConfigInvaildSchemaException
        self.name = config['name']
        self.ac = config['account']
        self.encPw = config['encPw']
        self.accountHash = config['hash']
        return

    @classmethod
    def patchLoad(cls, config_dir):
        if not os.path.isfile(config_dir):
            raise cls.AttributeErrorException
        try:
            config_data = configparser.ConfigParser()
            config_data.read(config_dir)
        except Exception:
            raise cls.ConfigDamagedException
        loaded = []
        try:
            config = {'total': {}}

            config['total']['ver'] = config_data.get('ADSLManager', 'version')
            config['total']['len'] = int(config_data.get('ADSLManager', 'config_sum'))
            for i in range(config['total']['len']):
                preLoadSection = config_data['ADSLConfig{}'.format(i + 1)]
                load_data = {
                    'name': preLoadSection['name'],
                    'account': preLoadSection['account'],
                    'encPw': preLoadSection['encPw'],
                    'hash': preLoadSection['hash']}
                logger.info('try append config index {}'.format(i + 1))
                loaded.append(ADSLClass(config=load_data))
                logger.debug('{} at line {} ADSLObject:{}'.format(str(sys._getframe().f_code.co_name),
                                                                  str(sys._getframe().f_lineno), repr(loaded)))
            logger.debug(
                '{} at line {} ADSLObject:{}'.format(str(sys._getframe().f_code.co_name), str(sys._getframe().f_lineno),
                                                     repr(loaded)))
        except Exception:
            raise cls.ConfigInvaildSchemaException
        logger.debug(
            '{} at line {} ADSLObject:{}'.format(str(sys._getframe().f_code.co_name), str(sys._getframe().f_lineno),
                                                 repr(loaded)))
        return loaded


# raise RuntimeError('没写完')
global ADSLObject, logger
# noinspection PyRedeclaration
ADSLObject = []
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger()
logFileStream = open(LOGFILE, 'a')
loghandle = logging.StreamHandler(logFileStream)
loghandle.setLevel(logging.INFO)
loghandle.set_name('adslmanager')
logFormatter = logging.Formatter(
    fmt='%(asctime)s [%(filename)s - %(funcName)s - %(lineno)d] %(process)d-%(thread)d-%(threadName)s %(levelname)s:%(message)s',
    datefmt='%a, %d %b %Y %H:%M:%S'
)
loghandle.setFormatter(logFormatter)
if DEBUGMODE:
    loghandle.setLevel(logging.DEBUG)
    loghandle.set_name('adslmanager_DEBUG')
for nowh in logger.handlers:
    logger.removeHandler(nowh)
logger.addHandler(loghandle)


class FlushThread(threading.Thread):

    def __init__(self, *args, tname=None,**kwargs):
        tname=tname or 'FlushThread'
        super().__init__(name=tname,**kwargs)
        self.exitFlag = False

    def run(self):
        inputThread = threading.Thread(target=input, daemon=True)
        inputThread.start()
        logger.debug('thread run')
        while not self.exitFlag:
            pass
        print('\b')
        logger.debug('thread over')

    def stop(self):
        if self.is_alive():
            self.exitFlag = True
            logger.debug('thread stop single sent')


# noinspection PyProtectedMember
class cmdUI(object):
    # class errors(object):
    global ADSLObject

    class ADSLManagerBaseErrors(ADSLManagerBaseDIYException):
        pass

    class SystemInteralError(ADSLManagerBaseErrors):
        def __init__(self, exc: Exception):
            UUid = str(uuid.uuid1())
            logger.error('Interal Errors Found UUID:{}'.format(UUid), exc_info=exc)
            print(cmdUI.UISpiltLineFormat('''
            出现内部错误，请根据UUID以及日志查错
            UUID:{}
            '''.format(UUid)))
            # sys.exc_clear
            return

        class SystemInteralErrorFlag(ADSLManagerBaseDIYException):
            pass

        @classmethod
        def new(cls, msg: str = None):
            return cls(cls.SystemInteralErrorFlag(msg))

    class UserError(ADSLManagerBaseErrors):
        def __init__(self, exc: Exception):
            UUid = str(uuid.uuid1())
            logger.error('User Caused Errors Found UUID:{}'.format(UUid), exc_info=exc)
            print(cmdUI.UISpiltLineFormat('''
            用户输入信息有误，请根据UUID以及日志查错
            UUID:{}
            错误简报：{}
            '''.format(UUid, repr(exc))))
            # sys.exc_clear
            return

        class UserErrorFlag(ADSLManagerBaseDIYException):
            pass

        @classmethod
        def new(cls, msg: str = None):
            return cls(cls.UserErrorFlag(msg))

    def __init__(self):
        self.nowConfigFile = None

    @staticmethod
    def clear():
        os.system('cls')
        logger.debug('screen cleared')

    # noinspection PyUnresolvedReferences
    @staticmethod
    def waitPress() -> keyboard.Key:
        """

        :rtype: keyboard.Key
        :return: 上一个按下的按键，即使焦点不在屏幕也会返回
        """
        # global key
        key: [None, keyboard.Key] = None
        ispressed = False

        def onPress(nowkey):
            logger.debug('key {} down'.format(str(nowkey)))
            nonlocal key
            key = nowkey
            nonlocal ispressed
            ispressed = True

        def onFin(nowkey):
            logger.debug('key {} on'.format(str(nowkey)))
            if not ispressed:
                return True
            return False

        with keyboard.Listener(on_press=onPress, on_release=onFin,name='keyWatchThread') as listener:
            listener.join()
            sys.stdin.flush()
            flushThread = FlushThread(target=input, daemon=True)
            flushThread.start()
            flushThread.stop()
            flushThread.join()
            # keyboard.Controller().press(key=keyboard.Key.enter)
            # keyboard.Controller().release(key=keyboard.Key.enter)
        logger.debug(
            '{} at line {} return key {}'.format(str(sys._getframe().f_code.co_name), str(sys._getframe().f_lineno),
                                                 str(key)))
        return key

    def getKeyCode(self, c: str):
        if c is None:
            return None
        if type(c) != str or len(c) != 1:
            raise self.SystemInteralError.new('this func can only accept ONE CHAR')
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

    # noinspection PyUnresolvedReferences
    def loadConf(self, dir):
        self.clear()
        print('正在尝试加载：{}'.format(dir))
        logger.info('try load config:{}'.format(dir))
        time.sleep(1)
        global ADSLObject
        try:

            ADSLObject = ADSLClass.patchLoad(dir)
            logger.debug(
                '{} at line {} ADSLObject:{}'.format(str(sys._getframe().f_code.co_name), str(sys._getframe().f_lineno),
                                                     repr(ADSLObject)))
        except ADSLClass.ADSLErrors as e:
            raise self.UserError(e)
        except Exception as e:
            raise self.SystemInteralError(e)
        print('\n加载成功')
        logger.debug(
            '{} at line {} ADSLObject:{}'.format(str(sys._getframe().f_code.co_name), str(sys._getframe().f_lineno),
                                                 repr(ADSLObject)))
        self.nowConfigFile = dir
        time.sleep(2)
        self.menuAfterLoad()

    @staticmethod
    def createConf():
        ans_config = configparser.ConfigParser()
        ans_config['ADSLManager'] = {
            'version': '1.0.0',
            'config_sum': 0}
        with open(DEFAULT_CONFIG_DIR, 'w+') as f:
            ans_config.write(f)
            logger.info('create default config')
            print('创建初始文件成功')
        return

    # noinspection PyUnresolvedReferences
    def mainMenu(self):
        self.clear()
        if os.path.isfile(DEFAULT_CONFIG_DIR):
            if os.path.exists(DEFAULT_CONFIG_DIR):
                logger.info('found one exist default data')
                print('''
                发现一个配置文件。是否需要加载？
                文件路径:{}
                按y开始加载'''.format(os.path.abspath(DEFAULT_CONFIG_DIR)))
                key = self.waitPress()
                if key == self.getKeyCode('y') or key == self.getKeyCode('Y'):
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
            nowkey = self.waitPress()
            logger.debug(
                '{} at line {} got key {}'.format(str(sys._getframe().f_code.co_name), str(sys._getframe().f_lineno),
                                                  str(nowkey)))
            if nowkey == self.getKeyCode('1'):
                self.clear()
                # print()
                input_dir = input('请输入路径：')
                if not (os.path.isfile(input_dir) and os.path.exists(input_dir)):
                    print('没有找到该文件，请重试')
                    continue
                self.loadConf(input_dir)
                return
            if nowkey == self.getKeyCode('2'):
                ADSLClass.status()
                continue
            if nowkey == self.getKeyCode('4'):
                self.clear()
                print('感谢使用')
                logger.info('exit by user')
                exit(0)
            if nowkey == self.getKeyCode('3'):
                try:
                    self.createConf()
                except Exception as e:
                    raise self.SystemInteralError(e)
                self.loadConf(DEFAULT_CONFIG_DIR)
                return

    @classmethod
    def UISpiltLineFormat(cls, origin_str: str, line_char: str = '-'):
        if line_char is None or line_char == '':
            return origin_str
        if not len(line_char) == 1:
            raise cls.SystemInteralError.new('the attribute line_char can only accept one char')
        lineList = origin_str.splitlines(False)
        lineNum = -1
        for index, thisline in enumerate(lineList):
            logger.debug('deal line {}:{}'.format(index, thisline))
            if len(thisline) == 0:
                logger.debug('skip line {}'.format(index))
                continue
            while len(thisline) != 0 and thisline[0] == ' ':
                lineList[index] = thisline[1:]
                thisline = lineList[index]
                logger.debug('cut space at line {}'.format(index))
            lineNum = max(lineNum, len(thisline))
            logger.debug('deal line {} fin.lineNum:{}'.format(index, len(thisline)))
        logger.debug('linenum:{} linestr:{}'.format(lineNum, line_char))
        origin_str = '\n'.join(lineList)
        return '\n' + line_char * lineNum + '\n' + origin_str + '\n' + line_char * lineNum + '\n'

    def waitQualifiedPress(self, wait_key: [str, list]):
        if type(wait_key) == str:
            if len(wait_key) != 1:
                raise self.SystemInteralError.new('this func can only accept ONE CHAR or a list made up of them')
            wait_key = [wait_key]
        elif type(wait_key) == list:
            for nowkey in wait_key:
                if type(nowkey) != str or len(nowkey) != 1:
                    raise self.SystemInteralError.new('this func can only accept ONE CHAR or a list made up of them')
        else:
            raise self.SystemInteralError.new('this func can only accept ONE CHAR or a list made up of them')
        for nowkeyindex in range(len(wait_key)):
            wait_key[nowkeyindex] = self.getKeyCode(wait_key[nowkeyindex])
        while True:
            nowkey = self.waitPress()
            if nowkey in wait_key:
                return nowkey.char

    def menuAfterLoad(self):
        self.clear()
        print(self.UISpiltLineFormat('''
        加载文件信息：
        文件名：{} 存档版本号：就没更新过有个锤子用 总文件数：{}
        '''.format(self.nowConfigFile, len(ADSLObject))))
        print('按下一个按钮执行操作')
        liststr = ''
        for index, now in enumerate(ADSLObject):
            liststr += '{}.{}\n'.format(str(index + 1), now.getName())
        print(self.UISpiltLineFormat('''

        {}
        
        0.断开连接
        1.启动链接选择界面
        U.查询当前状态
        X.退出程序
        S.保存当前配置文件
        A.添加一个链接配置
        D.删除一个连接配置
        '''.format(self.UISpiltLineFormat(liststr or '没有找到啥链接。请添加几个', '#')), '*'))
        while True:
            print('\n请按下你需要的操作的对应按键\n')
            nowkey = self.waitQualifiedPress(['0', '1', 'u', 'U', 'x', 'X', 's', 'S', 'a', 'A', 'd', 'D'])
            if nowkey == '0':
                if liststr is None:
                    print('\n别搞事，傻逼，给爷从头选操作')
                    continue
                index = input('请输入你想咔掉的链接编号：')
                if (not index.isdigit()) and (not (1 <= int(index) <= len(ADSLObject) + 1)):
                    print('\n别搞事，傻逼，给爷从头选操作')
                    continue
                self.disconnecting(index)
                self.menuAfterLoad()
                return
            if nowkey == '1':
                if liststr is None:
                    print('\n别搞事，傻逼，给爷从头选操作')
                    continue
                index = int(input('请输入你想用的链接编号：'))
                if not (1 <= index <= len(ADSLObject) + 1):
                    print('\n别搞事，傻逼，给爷从头选操作')
                    continue
                self.connecting(index)
                self.menuAfterLoad()
                return
            if nowkey == 'U' or nowkey == 'u':
                print('n')
                ADSLClass.status()
                continue
            if nowkey == 'X' or nowkey == 'x':
                print('感谢使用')
                exit(0)
            if nowkey == 'S' or nowkey == 's':
                print('正在尝试保存')
                logger.info('try saving file at {}'.format(self.nowConfigFile))
                try:
                    ADSLClass.save(ADSLObject, self.nowConfigFile)
                except Exception as e:
                    print('保存失败')
                    raise self.SystemInteralError(e)
                print(self.UISpiltLineFormat('保存成功\n保存位置：{}'.format(os.path.abspath(self.nowConfigFile))))
                continue
            if nowkey == 'a' or nowkey == 'A':
                self.addConfig()
                self.menuAfterLoad()
                return
            if nowkey == 'd' or nowkey == 'D':
                self.delConfig()
                self.menuAfterLoad()
                return
        return

    def connecting(self, config_index):
        config_index -= 1
        nowConf = ADSLObject[config_index]
        self.clear()
        print(self.UISpiltLineFormat('''
        链接名称：{}
        账号：{}
        '''.format(nowConf.getName(), nowConf.getAccount())))
        order = input('请输入口令:')
        try:
            nowConf.callInternet(order)
        except ADSLClass.PasswordVerifyFailedException as e:
            logger.warning('password verify failed', exc_info=e)
            self.UserError.new('密码错误')
            print('按任意键返回上一级菜单')
            self.waitPress()
            return
        except Exception as e:
            raise self.SystemInteralError(e)
        logger.info('link to {} complete'.format(nowConf.getName()))
        print(self.UISpiltLineFormat('''
        连接成功！
        按任意键返回上一级菜单
        '''))
        self.waitPress()
        return

    def disconnecting(self, config_index):
        config_index -= 1
        nowConf = ADSLObject[config_index]
        print(self.UISpiltLineFormat('''
        即将尝试解除连接
        链接名称：{}
        账户：{}
        '''.format(nowConf.getName(), nowConf.getAccount())))
        nowConf.disconnect()
        logger.info('disconnect {} by user'.format(nowConf.getName()))
        print('完成，请按任意键返回')
        self.waitPress()
        return

    def addConfig(self):
        self.clear()
        name = input('账户名称（不是账号）：')
        ac = input('账号：')
        pw = input('密码：')
        order = input('口令（用于加密密码，无法修改或找回：')
        self.clear()
        print(self.UISpiltLineFormat('''
        请确认：
        链接名称：{}
        账号：{}
        密码：{}
        链接口令：{}
        按y确认，按n拒绝并返回上一级菜单
        '''.format(name, ac, pw, order)))
        nowkey = self.waitQualifiedPress(['y', 'Y', 'n', 'N'])
        if nowkey == 'n' or nowkey == 'N':
            return
        print('正在尝试添加 请稍后')
        try:
            ADSLObject.append(ADSLClass(name, ac, pw, order))
        except Exception as e:
            raise self.SystemInteralError(e)
        logger.info('add {} complete'.format(name))
        print('成功！按任意键返回')
        self.waitPress()
        return

    def delConfig(self):
        liststr = '\n'
        for index, now in enumerate(ADSLObject):
            liststr += '{}.{}\n'.format(str(index + 1), now.getName())
        print(self.UISpiltLineFormat('''
        {}
        请输入你要删除的数字，输入不在范围的数字或者其他奇怪的东西将会
        返回上一级菜单
        '''.format(liststr)))
        num = input()
        if (not num.isdigit()) or (not (1 <= int(num) <= len(ADSLObject))):
            return
        num = int(num)
        logger.info('del object {} by user'.format(ADSLObject[num - 1].getName()))
        del ADSLObject[num - 1]
        print('删除成功，按任意键返回上一级菜单')
        self.waitPress()
        return


if __name__ == '__main__':
    # print(ADSLClass(1,1,1,1),cmdUI())
    # input()
    nowInstance = cmdUI()
    try:
        nowInstance.index()
        nowInstance.mainMenu()
    except ADSLManagerBaseDIYException as e:
        logger.error('program exit by custom errors', exc_info=e)
        print('程序异常退出')
        exit(1)
    except Exception as e:
        logger.error('program exit by unknown errors', exc_info=e)
        print('发生未知错误，请查询日志')
        exit(255)
