from os import getcwd
from os.path import expanduser, isdir


##-main
#---------Path variables
Cracker_running_path = getcwd()
Cracker_data_path = Cracker_running_path + '/Data'

#------Home mode
if isdir(expanduser('~/.RSA_keys')):
    home = True

else:
    home = False

