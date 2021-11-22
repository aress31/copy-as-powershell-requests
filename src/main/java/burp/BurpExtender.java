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

public class BurpExtender implements IBurpExtender {

  public static final String EXTENSION = "Copy as PowerShell Requests";

  @Override
  public void registerExtenderCallbacks(IBurpExtenderCallbacks burpExtenderCallbacks) {
    ContextMenuFactory contextMenuFactory = new ContextMenuFactory(burpExtenderCallbacks);

    burpExtenderCallbacks.setExtensionName(EXTENSION);

    burpExtenderCallbacks.registerContextMenuFactory(contextMenuFactory);
    burpExtenderCallbacks.printOutput("New 'Copy as PowerShell request(s)' option added to the context menu");
  }
}
