# copy-as-powershell-requests
[![BApp Store](https://img.shields.io/badge/BApp-Published-orange.svg)](https://portswigger.net/bappstore/4da25d602db04f5ca7c4b668e4611cfe)
[![Language](https://img.shields.io/badge/Lang-Java-blue.svg)](https://www.java.com)
[![Language](https://img.shields.io/badge/Lang-.NET-blue.svg)](https://www.microsoft.com/net/)
[![License](https://img.shields.io/badge/License-Apache%202.0-red.svg)](https://opensource.org/licenses/Apache-2.0)

## Copy as PowerShell request(s) plugin for Burp Suite
This extension copies the selected request(s) to the clipboard as PowerShell object assignments. Standard or Base64 formats are available, with Base64 being the best option for binary data such as file uploads. Copied data also includes the necessary command to [invoke the web request(s)](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-webrequest?view=powershell-5.1).</p>

## Project information
Suggestions for improvement, feedback and comments will be much appreciated.

## Installation
### Compilation 
#### Windows & Unix
1. Install gradle (<https://gradle.org/>)
2. Download the repository.
```shell
$ git clone https://github.com/AresS31/copy-as-powershell-requests
$ cd .\copy-as-powershell-requests\
```
3. Create the standalone jar:
```shell
$ gradle fatJar
```

### Burp Suite import
In Burp Suite, under the `Extender/Options` tab, click on the `Add` button and load the `copy-as-powershell-requests-all` jar file located in the `.\build\libs` folder.

## Possible improvements
- [ ] Source code optimisation.

## Credits
Original inspiration by [PortSwigger's copy as curl command function](http://releases.portswigger.net/2013/09/v1517.html).

## License
Copyright 2018 Alexandre Teyar

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

<http://www.apache.org/licenses/LICENSE-2.0>

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
