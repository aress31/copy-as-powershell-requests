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

package copy_as_powershell_requests.utils;

import java.util.List;
import java.util.Map;

import org.apache.commons.text.translate.CharSequenceTranslator;
import org.apache.commons.text.translate.LookupTranslator;

public final class StaticData {

  public static final int IWR_MAXIMUM_REDIRECTION = 0;
  public static final String IWR_BASIC_INVOCATION = "Invoke-WebRequest -Method $method -Uri $URI -MaximumRedirection $maximumRedirection -Headers $headers ";
  // https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-webrequest
  public static final List<String> SUPPORTED_METHODS = List.of("DEFAULT", "GET", "HEAD", "POST", "PUT", "DELETE",
      "TRACE", "OPTIONS", "MERGE", "PATCH");
  public static final List<String> SKIP_HEADERS = List.of("connection", "content-length", "cookie");
  // reference used for escaping rules: https://ss64.com/ps/syntax-esc.html
  public static final CharSequenceTranslator ESCAPE_POWERSHELL = new LookupTranslator(
      Map.of("`", "``", "#", "`#", "\"", "`\"", "'", "`'", "$", "`$"));

  private StaticData() {
    // not called
  }
}
