/*
 * Copyright 2018 Alexandre Teyar
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package burp;

import static copy_as_powershell_requests.utils.StaticData.EXTENSION_NAME;

import copy_as_powershell_requests.utils.ExtensionHelper;
import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;

public class BurpExtender implements IBurpExtender {

  @Override
  public void registerExtenderCallbacks(IBurpExtenderCallbacks burpExtenderCallbacks) {
    Clipboard systemClipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
    ExtensionHelper extensionHelper = new ExtensionHelper(burpExtenderCallbacks);
    ContextMenuFactory contextMenuFactory = new ContextMenuFactory(burpExtenderCallbacks,
        extensionHelper,
        systemClipboard);
    burpExtenderCallbacks.setExtensionName(EXTENSION_NAME);
    burpExtenderCallbacks.registerContextMenuFactory(contextMenuFactory);
    burpExtenderCallbacks
        .printOutput("New entries have been added to the Burp Suite context menu.");
  }
}
