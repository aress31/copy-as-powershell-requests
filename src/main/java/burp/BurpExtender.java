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

import copy_as_powershell_requests.utils.ExtensionHelpers;
import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;

public class BurpExtender implements IBurpExtender {

  @Override
  public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
    Clipboard systemClipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
    ExtensionHelpers extensionHelpers = new ExtensionHelpers(callbacks);
    ContextMenuFactory contextMenuFactory = new ContextMenuFactory(extensionHelpers,
        systemClipboard);
    callbacks.setExtensionName(EXTENSION_NAME);
    callbacks.registerContextMenuFactory(contextMenuFactory);
    callbacks.printOutput("New entries have been added to the Burp Suite contextual menu.");
  }
}
