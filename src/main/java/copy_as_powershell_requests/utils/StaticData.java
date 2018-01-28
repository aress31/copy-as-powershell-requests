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

package copy_as_powershell_requests.utils;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import org.apache.commons.text.translate.CharSequenceTranslator;
import org.apache.commons.text.translate.LookupTranslator;

public class StaticData {

  public final static String EXTENSION_NAME = "Copy as PowerShell request(s)";
  public final static int IWR_MAXIMUM_REDIRECTION = 0;
  public final static String IWR_BASIC_INVOCATION =
      "Invoke-WebRequest -Method $method -Uri $URI -MaximumRedirection $maximumRedirection -Headers $headers ";
  // reference used for methods:
  // https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-webrequest
  public final static List<String> SUPPORTED_METHODS = Arrays
      .asList("DEFAULT", "GET", "HEAD", "POST", "PUT", "DELETE", "TRACE", "OPTIONS", "MERGE",
          "PATCH");
  public final static List<String> SKIP_HEADERS = Arrays
      .asList("connection", "content-length", "cookie");
  // reference used for escaping rules: https://ss64.com/ps/syntax-esc.html
  public static final CharSequenceTranslator ESCAPE_POWERSHELL = new LookupTranslator(
      Map.of("`", "``", "#", "`#", "\"", "`\"", "'", "`'")
  );
}
