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

import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.ClipboardOwner;
import java.awt.datatransfer.StringSelection;
import java.awt.datatransfer.Transferable;
import java.util.ArrayList;
import java.util.List;
import javax.swing.JMenuItem;

public class ContextMenuFactory implements IContextMenuFactory, ClipboardOwner {

  private IBurpExtenderCallbacks callbacks;
  private Clipboard systemClipboard;
  private ExtensionHelpers extensionHelpers;

  ContextMenuFactory(IBurpExtenderCallbacks callbacks, ExtensionHelpers extensionHelpers,
      Clipboard systemClipboard) {
    this.callbacks = callbacks;
    this.extensionHelpers = extensionHelpers;
    this.systemClipboard = systemClipboard;
  }

  @Override
  public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
    List<JMenuItem> jMenuItems = new ArrayList<>();
    JMenuItem copy_as_powershell_request = new JMenuItem("Copy as PowerShell request(s)");
    copy_as_powershell_request.addActionListener(e -> {
      StringBuilder stringBuilder = new StringBuilder();

      for (IHttpRequestResponse selectedMessage : invocation.getSelectedMessages()) {
        stringBuilder.append(this.extensionHelpers.buildPowershellRequest(selectedMessage));
        stringBuilder.append(System.lineSeparator()).append(System.lineSeparator());
      }

      // delete the last line separator
      stringBuilder
          .delete(stringBuilder.lastIndexOf(System.lineSeparator()), stringBuilder.length());

      this.callbacks.printOutput(stringBuilder.toString());
      this.systemClipboard.setContents(new StringSelection(stringBuilder.toString()), this);
    });

    jMenuItems.add(copy_as_powershell_request);
    return jMenuItems;
  }

  @Override
  public void lostOwnership(Clipboard clipboard, Transferable contents) {
  }
}
