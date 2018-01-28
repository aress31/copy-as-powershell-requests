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

import copy_as_powershell_requests.utils.ExtensionHelper;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.ClipboardOwner;
import java.awt.datatransfer.StringSelection;
import java.awt.datatransfer.Transferable;
import java.util.ArrayList;
import java.util.List;
import javax.swing.JMenuItem;

public class ContextMenuFactory implements IContextMenuFactory, ClipboardOwner {

  private IBurpExtenderCallbacks burpExtenderCallbacks;
  private Clipboard systemClipboard;
  private ExtensionHelper extensionHelper;

  ContextMenuFactory(IBurpExtenderCallbacks burpExtenderCallbacks,
      ExtensionHelper extensionHelper,
      Clipboard systemClipboard) {
    this.burpExtenderCallbacks = burpExtenderCallbacks;
    this.extensionHelper = extensionHelper;
    this.systemClipboard = systemClipboard;
  }

  @Override
  public List<JMenuItem> createMenuItems(IContextMenuInvocation contextMenuInvocation) {
    List<JMenuItem> jMenuItems = new ArrayList<>();
    JMenuItem copyAsPowershellRequests = new JMenuItem("Copy as PowerShell request(s)");
    copyAsPowershellRequests
        .addActionListener(e -> copyAsPowershellRequests(contextMenuInvocation, false));

    JMenuItem copyAsPowershellRequestsBase64 = new JMenuItem(
        "Copy as PowerShell request(s) (base64-encoded body)");
    copyAsPowershellRequestsBase64
        .addActionListener(e -> copyAsPowershellRequests(contextMenuInvocation, true));

    jMenuItems.add(copyAsPowershellRequests);
    jMenuItems.add(copyAsPowershellRequestsBase64);
    return jMenuItems;
  }

  private void copyAsPowershellRequests(IContextMenuInvocation contextMenuInvocation,
      boolean isBase64) {
    StringBuilder stringBuilder = new StringBuilder();

    for (IHttpRequestResponse selectedMessage : contextMenuInvocation.getSelectedMessages()) {
      if (selectedMessage.getRequest() != null) {
        stringBuilder
            .append(this.extensionHelper.buildPowershellRequest(selectedMessage, isBase64));
        stringBuilder.append(System.lineSeparator()).append(System.lineSeparator());
      } else {
        this.burpExtenderCallbacks.issueAlert(
            "The selected request is null.");
      }
    }

    // delete the last line separator
    if (stringBuilder.length() > 0) {
      stringBuilder
          .delete(stringBuilder.lastIndexOf(System.lineSeparator()), stringBuilder.length());
    }

    this.systemClipboard.setContents(new StringSelection(stringBuilder.toString()), this);
  }

  @Override
  public void lostOwnership(Clipboard clipboard, Transferable contents) {
  }
}
