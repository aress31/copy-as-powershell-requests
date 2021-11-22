/*
 * Copyright 2018 - 2021 Alexandre Teyar
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

import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.ClipboardOwner;
import java.awt.datatransfer.StringSelection;
import java.awt.datatransfer.Transferable;
import java.util.ArrayList;
import java.util.List;
import java.util.StringJoiner;

import javax.swing.JMenuItem;

import copy_as_powershell_requests.utils.ExtensionHelper;

public class ContextMenuFactory implements IContextMenuFactory, ClipboardOwner {

  private IBurpExtenderCallbacks burpExtenderCallbacks;
  private Clipboard systemClipboard;
  private ExtensionHelper extensionHelper;

  ContextMenuFactory(IBurpExtenderCallbacks burpExtenderCallbacks) {
    this.burpExtenderCallbacks = burpExtenderCallbacks;
    this.extensionHelper = new ExtensionHelper(burpExtenderCallbacks);
    this.systemClipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
  }

  @Override
  public List<JMenuItem> createMenuItems(IContextMenuInvocation contextMenuInvocation) {
    List<JMenuItem> jMenuItems = new ArrayList<>();
    JMenuItem copyAsPowershellRequests = new JMenuItem("Copy as PowerShell request(s)");
    copyAsPowershellRequests.addActionListener(e -> copyAsPowershellRequests(contextMenuInvocation, false));

    JMenuItem copyAsPowershellRequestsBase64 = new JMenuItem("Copy as PowerShell request(s) (base64-encoded body)");
    copyAsPowershellRequestsBase64.addActionListener(e -> copyAsPowershellRequests(contextMenuInvocation, true));

    jMenuItems.add(copyAsPowershellRequests);
    jMenuItems.add(copyAsPowershellRequestsBase64);

    return jMenuItems;
  }

  private void copyAsPowershellRequests(IContextMenuInvocation contextMenuInvocation, boolean isBase64) {
    StringJoiner stringJoiner = new StringJoiner("");

    for (IHttpRequestResponse selectedMessage : contextMenuInvocation.getSelectedMessages()) {
      if (selectedMessage.getRequest() != null) {
        stringJoiner.add(this.extensionHelper.buildPowershellRequest(selectedMessage, isBase64))
            .add(System.lineSeparator()).add(System.lineSeparator());
      } else {
        this.burpExtenderCallbacks.issueAlert("The selected request is null.");
        this.burpExtenderCallbacks.printError("The selected request is null.");
      }
    }

    this.systemClipboard.setContents(new StringSelection(stringJoiner.toString()), this);
  }

  @Override
  public void lostOwnership(Clipboard clipboard, Transferable contents) {
    // Dummy comment
  }
}
