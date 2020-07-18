# CyberSecurity2020

CyberSecurity project for Università degli Studi di Salerno. Academic year 2019/2020. 

## Team members

* [Giovanni Ammendola](https://github.com/giorge1)
* [Giovanni Mignone](https://github.com/giomig)
* [Vincenzo Petrone](https://github.com/v8p1197)
* [Luigi Terrone](https://github.com/LuigiTer)
* [Luca Tramuto](https://github.com/ltramuto)

## Documentation

See the [documentation](https://github.com/v8p1197/CyberSecurity2020/blob/master/ReportCyberSecurity2020.pdf)
to understand the goals of the project.

## Usage

### Prerequisites

In order to use the software you need:
*   [Python](https://www.python.org/downloads/) ≥ 3.6
*   [OpenSSL](https://www.openssl.org/source/)
*   [Git](https://git-scm.com/downloads) (Required if you are using a Windows OS)

### Commands

The command sequence follows the one given in the [documentation](https://github.com/v8p1197/CyberSecurity2020/blob/master/ReportCyberSecurity2020.pdf).

#### Linux

If you are using a Linux OS, follow these instructions:
1.  Open the shell on the directory `TestCrypto`
2.  Run the command `sh generation_script_linux.sh`
3.  Run the command `cd server`
    * Run the server python script with `python3 server.py`
4.  Open another shell on the directory `TestCrypto/sender`
    *   Run the sender python script with `python3 script_sender.py 0` to simulate a non-infected-user-like behavior
    *   Run the sender python script with `python3 script_sender.py 1` to simulate an infected-user-like behavior
5.  Open another shell on the directory `TestCrypto/receiver`
    *   Run the receiver python script with `python3 script_receiver.py 0` to simulate a honest-user-like behavior
    *   Run the receiver python script with `python3 script_receiver.py 1` to simulate an adversary-like behavior

#### Windows

If you are using a Windows OS, follow these instructions:
1.  Open the shell on the directory `TestCrypto`
2.  Run the command `sh generation_script_windows.sh`
3.  Run the command `cd server`
    *   Run the server python script with `python server.py`
4.  Open another shell on the directory `TestCrypto/sender`
    *   Run the sender python script with `python script_sender.py 0` to simulate a non-infected-user-like behavior
    *   Run the sender python script with `python script_sender.py 1` to simulate an infected-user-like behavior
5.  Open another shell on the directory `TestCrypto/receiver`
    *   Run the receiver python script with `python script_receiver.py 0` to simulate a honest-user-like behavior
    *   Run the receiver python script with `python script_receiver.py 1` to simulate an adversary-like behavior

If you get an error like `sh is not recognized as an internal or external command, operable program or batch file`,
follow these instructions:
1.  Install [Git](https://git-scm.com/downloads) in your computer
2.  After installing Git, go to the foler in which Git in installed
    * Mostly it will be in `C drive` and then
`Program Files` folder
3.  In `Program Files` folder, you will find the folder named `Git`, find the `bin` folder which is inside `usr` folder
in the `Git` folder
    * For example, the location is `C:\Program Files\Git\usr\bin`
4.  Add this location (`C:\Program Files\Git\usr\bin`) in `path` variable, in **system environment variables**
5.  You are done. Restart `cmd` and try to run `ls` or other Linux commands
6.  Follow the above instructions again to run the software
