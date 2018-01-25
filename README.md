# copy-as-powershell-requests
[![Language](https://img.shields.io/badge/Lang-Java-blue.svg)](https://www.java.com)
[![Language](https://img.shields.io/badge/Lang-.NET-blue.svg)](https://www.microsoft.com/net/)
[![License](https://img.shields.io/badge/License-Apache%202.0-red.svg)](https://opensource.org/licenses/Apache-2.0)

## Copy as PowerShell request(s) plugin for the Burp Suite
Copies selected request(s) as [PowerShell request(s) invocation](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-webrequest?view=powershell-5.1). 

## Project information
The extension is still in development, feedback and comments are much appreciated.

### Known issues
Requests containing in body parameters of the following types are not fully supported yet:
* PARAM_MULTIPART_ATTR - Web Cmdlets in PowerShell versions prior to 6.0.0-beta.8 do not support the submission of multipart/form-data, see https://github.com/PowerShell/PowerShell/pull/4782.
* PARAM_XML
* PARAM_XML_ATTR

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

### Burp Suite settings
In the Burp Suite, under the `Extender/Options` tab, click on the `Add` button and load the `copy-as-powershell-requests-all` jarfile located in the `.\build\libs` folder. 

## Possible Improvements
- [ ] Add new features.
- [ ] Source code optimisation.
- [ ] Support for more additional parameter types.

## Credits
Original inspiration by [PortSwigger's python requests extension](https://github.com/PortSwigger/copy-as-python-requests).

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
