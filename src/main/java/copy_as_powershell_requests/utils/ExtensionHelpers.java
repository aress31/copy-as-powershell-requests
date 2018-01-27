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

import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IParameter;
import burp.IRequestInfo;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import org.apache.commons.text.StringEscapeUtils;

public class ExtensionHelpers {

  private IBurpExtenderCallbacks burpExtenderCallbacks;
  private int maximumRedirection = 0;
  private boolean hasContentType;
  private boolean hasBodyParams;
  private boolean hasCookieParams;
  private boolean hasURLParams;
  private boolean hasUserAgent;

  public ExtensionHelpers(IBurpExtenderCallbacks burpExtenderCallbacks) {
    this.burpExtenderCallbacks = burpExtenderCallbacks;
  }

  public StringBuilder buildPowershellRequest(
      IHttpRequestResponse selectedMessage, boolean isBase64) {
    IRequestInfo requestInfo = this.burpExtenderCallbacks.getHelpers()
        .analyzeRequest(selectedMessage);
    StringBuilder stringBuilder = new StringBuilder();
    String method = StringEscapeUtils.builder(StaticData.ESCAPE_POWERSHELL)
        .escape(requestInfo.getMethod()).toString();
    String URI = StringEscapeUtils.builder(StaticData.ESCAPE_POWERSHELL)
        .escape(requestInfo.getUrl().toString()).toString();

    stringBuilder.append("$method = [Microsoft.PowerShell.Commands.WebRequestMethod]::")
        .append(method)
        .append(System.lineSeparator()).append("$URI = [System.Uri]::new(\"").append(URI)
        .append("\")")
        .append(System.lineSeparator()).append("$maximumRedirection = [System.Int32] ")
        .append(this.maximumRedirection)
        .append(System.lineSeparator());
    stringBuilder.append(processHeaders(requestInfo.getHeaders()));
    stringBuilder.append(processParams(requestInfo.getParameters()));
    stringBuilder.append(processBody(selectedMessage, requestInfo, isBase64));
    stringBuilder.append(
        "Invoke-WebRequest -Method $method -Uri $URI -MaximumRedirection $maximumRedirection -Headers $headers ");

    if (this.hasContentType) {
      stringBuilder.append("-ContentType $contentType ");
    }

    if (this.hasUserAgent) {
      stringBuilder.append("-UserAgent $userAgent ");
    }

    if (this.hasCookieParams) {
      stringBuilder.append("-WebSession $session ");
    }

    if (this.hasBodyParams) {
      if (!(stringBuilder.toString().contains("-Body"))) {
        stringBuilder.append("-Body $BodyParams ");
      } else {
        stringBuilder.append(", $BodyParams");
      }
    }

    if (this.hasURLParams) {
      if (!(stringBuilder.toString().contains("-Body"))) {
        stringBuilder.append("-Body $URLParams ");
      } else {
        stringBuilder.append(", $URLParams");
      }
    }

    return stringBuilder;
  }

  private StringBuilder processHeaders(List<String> headers) {
    this.hasContentType = false;
    this.hasUserAgent = false;
    StringBuilder stringBuilder = new StringBuilder(
        "$headers = [System.Collections.Generic.Dictionary[string,string]]::new()")
        .append(System.lineSeparator());

    // skip the first header line
    for (String header : headers.subList(1, headers.size())) {
      String headerName = StringEscapeUtils.builder(StaticData.ESCAPE_POWERSHELL)
          .escape((header.split(": ")[0] + "")).toString();
      String headerValue = StringEscapeUtils.builder(StaticData.ESCAPE_POWERSHELL)
          .escape((header.split(": ")[1] + "")).toString();

      if (!(StaticData.FORBIDDEN_HEADERS.contains(headerName.toLowerCase()))) {
        switch (header.split(": ")[0].toLowerCase()) {
          case "content-type":
            this.hasContentType = true;
            stringBuilder.append("$contentType = (\"").append(headerValue).append("\")")
                .append(System.lineSeparator());
            break;
          case "user-agent":
            this.hasUserAgent = true;
            stringBuilder.append("$userAgent = (\"").append(headerValue).append("\")")
                .append(System.lineSeparator());
            break;
          default:
            stringBuilder.append("$headers.Add(\"").append(headerName).append("\", \"")
                .append(headerValue).append("\")")
                .append(System.lineSeparator());
            break;
        }
      }
    }

    return stringBuilder;
  }

  private StringBuilder processParams(List<IParameter> parameters) {
    this.hasCookieParams = false;
    this.hasURLParams = false;
    boolean isCookieFirstIteration = true;
    boolean isURLFirstIteration = true;
    StringBuilder stringBuilder = new StringBuilder();

    if (!(parameters.isEmpty())) {
      for (IParameter parameter : parameters) {
        String parameterName = StringEscapeUtils.builder(StaticData.ESCAPE_POWERSHELL)
            .escape(parameter.getName()).toString();
        String parameterValue = StringEscapeUtils.builder(StaticData.ESCAPE_POWERSHELL)
            .escape(parameter.getValue()).toString();

        switch (parameter.getType()) {
          case IParameter.PARAM_URL:
            if (isURLFirstIteration) {
              this.hasURLParams = true;
              stringBuilder.append(
                  "$URLParams = [System.Collections.Generic.Dictionary[string,string]]::new()")
                  .append(System.lineSeparator());
              isURLFirstIteration = false;
            }

            stringBuilder.append("$URLParams.Add(\"").append(parameterName).append("\", \"")
                .append(parameterValue).append("\")")
                .append(System.lineSeparator());
            break;
          case IParameter.PARAM_COOKIE:
            if (isCookieFirstIteration) {
              this.hasCookieParams = true;
              stringBuilder.append(
                  "$session = [Microsoft.PowerShell.Commands.WebRequestSession]::new()")
                  .append(System.lineSeparator());
              isCookieFirstIteration = false;
            }

            stringBuilder.append("$session.Cookies.Add($URI, [System.Net.Cookie]::new(\"")
                .append(parameterName).append("\", \"").append(parameterValue).append("\"))")
                .append(System.lineSeparator());
            break;
          default:
            break;
        }
      }
    }

    return stringBuilder;
  }

  private StringBuilder processBody(IHttpRequestResponse selectedMessage,
      IRequestInfo requestInfo, boolean isBase64) {
    this.hasBodyParams = false;
    int bodyOffset = requestInfo.getBodyOffset();
    byte[] request = selectedMessage.getRequest();
    StringBuilder stringBuilder = new StringBuilder();

    if (request.length > bodyOffset) {
      this.hasBodyParams = true;

      if (isBase64) {
        String postData = Base64.getEncoder()
            .encodeToString(Arrays.copyOfRange(request, bodyOffset, request.length));
        stringBuilder.append("$bodyParams64 = [System.String]::new(\"").append(postData)
            .append("\")")
            .append(System.lineSeparator()).append(
            "$bodyParams = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($bodyParams64))")
            .append(System.lineSeparator());
      } else {
        String postData = StringEscapeUtils.builder(StaticData.ESCAPE_POWERSHELL).escape(
            this.burpExtenderCallbacks.getHelpers()
                .bytesToString(Arrays.copyOfRange(request, bodyOffset, request.length))).toString();
        stringBuilder.append("$bodyParams = [System.String]::new(\"").append(postData).append("\")")
            .append(System.lineSeparator());
      }
    }

    return stringBuilder;
  }
}
