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
import java.util.List;
import org.apache.commons.text.StringEscapeUtils;

public class ExtensionHelpers {

  private IBurpExtenderCallbacks callbacks;
  private boolean hasContentType;
  private boolean hasParamBody;
  private boolean hasParamJson;
  private boolean hasParamMultipart;
  private boolean hasParamUrl;
  private boolean hasUserAgent;

  public ExtensionHelpers(IBurpExtenderCallbacks callbacks) {
    this.callbacks = callbacks;
  }

  public StringBuilder buildPowershellRequest(
      IHttpRequestResponse selectedMessage) {
    IRequestInfo requestInfo = this.callbacks.getHelpers().analyzeRequest(selectedMessage);
    StringBuilder stringBuilder = new StringBuilder();
    // prevents OS command injection
    String method = StringEscapeUtils.builder(StaticData.ESCAPE_POWERSHELL)
        .escape(requestInfo.getMethod()).toString();
    String uri = StringEscapeUtils.builder(StaticData.ESCAPE_POWERSHELL)
        .escape(requestInfo.getUrl().toString()).toString();

    stringBuilder.append("$method = [Microsoft.PowerShell.Commands.WebRequestMethod]::" + method)
        .append(System.lineSeparator()).append("$uri = [System.Uri]::new(\"" + uri + "\")")
        .append(System.lineSeparator());
    stringBuilder.append(processHeaders(requestInfo.getHeaders()));
    stringBuilder.append(processParameters(requestInfo.getParameters()));
    stringBuilder.append("Invoke-WebRequest -Method $method -Uri $uri -Headers $headers");

    if (this.hasContentType) {
      stringBuilder.append(" -ContentType $contentType");
    }

    if (this.hasUserAgent) {
      stringBuilder.append(" -UserAgent $userAgent");
    }

    if (this.hasParamBody) {
      if (!stringBuilder.toString().contains("-Body")) {
        stringBuilder.append(" -Body $paramBody");
      } else {
        stringBuilder.append(", $paramBody");
      }
    }

    if (this.hasParamJson) {
      if (!stringBuilder.toString().contains("-Body")) {
        stringBuilder.append(" -Body $paramJson");
      } else {
        stringBuilder.append(", $paramJson");
      }
    }

//    if (this.hasParamMultipart) {
//      if (!stringBuilder.toString().contains("-Body")) {
//        stringBuilder.append(" -Body $paramMultipart");
//      } else {
//        stringBuilder.append(", $paramMultipart");
//      }
//    }

    if (this.hasParamUrl) {
      if (!stringBuilder.toString().contains("-Body")) {
        stringBuilder.append(" -Body $paramUrl");
      } else {
        stringBuilder.append(", $paramUrl");
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
      // prevents OS command injection
      String headerName = StringEscapeUtils.builder(StaticData.ESCAPE_POWERSHELL)
          .escape((header.split(": ")[0] + "")).toString();
      String headerValue = StringEscapeUtils.builder(StaticData.ESCAPE_POWERSHELL)
          .escape((header.split(": ")[1] + "")).toString();

      if (!(headerName.toLowerCase().equals("connection") || headerName.toLowerCase()
          .equals("content-length"))) {
        switch (header.split(": ")[0].toLowerCase()) {
          case "content-type":
            this.hasUserAgent = true;
            stringBuilder.append("$contentType = (\"" + headerValue + "\")")
                .append(System.lineSeparator());
            break;
          case "user-agent":
            this.hasUserAgent = true;
            stringBuilder.append("$userAgent = (\"" + headerValue + "\")")
                .append(System.lineSeparator());
            break;
          default:
            stringBuilder.append(
                "$headers.Add(\"" + headerName + "\", \"" + headerValue + "\")")
                .append(System.lineSeparator());
            break;
        }
      }
    }

    return stringBuilder;
  }

  private StringBuilder processParameters(List<IParameter> parameters) {
    this.hasParamBody = false;
    this.hasParamJson = false;
    this.hasParamMultipart = false;
    this.hasParamUrl = false;
    boolean firstParamBody = true;
    boolean firstParamJson = true;
    boolean firstParamMultipart = true;
    boolean firstParamUrl = true;
    StringBuilder stringBuilder = new StringBuilder();

    if (!parameters.isEmpty()) {
      for (IParameter parameter : parameters) {
        // prevents OS command injection
        String parameterName = StringEscapeUtils.builder(StaticData.ESCAPE_POWERSHELL)
            .escape(parameter.getName()).toString();
        String parameterValue = StringEscapeUtils.builder(StaticData.ESCAPE_POWERSHELL)
            .escape(parameter.getValue()).toString();

        switch (parameter.getType()) {
          case IParameter.PARAM_BODY:
            if (firstParamBody) {
              this.hasParamBody = true;
              stringBuilder.append(
                  "$paramBody = [System.Collections.Generic.Dictionary[string,string]]::new()")
                  .append(System.lineSeparator());
              firstParamBody = false;
            }

            stringBuilder.append(
                "$paramBody.Add(\"" + parameterName + "\", \"" + parameterValue
                    + "\")")
                .append(System.lineSeparator());
            break;
          case IParameter.PARAM_JSON:
            if (firstParamJson) {
              this.hasParamJson = true;
              stringBuilder.append(
                  "$paramJson = [System.Collections.Generic.Dictionary[string,string]]::new()")
                  .append(System.lineSeparator());
              firstParamJson = false;
            }

            stringBuilder.append(
                "$paramJson.Add(\"" + parameterName + "\", \"" + parameterValue
                    + "\")")
                .append(System.lineSeparator());
            break;
          case IParameter.PARAM_URL:
            if (firstParamUrl) {
              this.hasParamUrl = true;
              stringBuilder.append(
                  "$paramUrl = [System.Collections.Generic.Dictionary[string,string]]::new()")
                  .append(System.lineSeparator());
              firstParamUrl = false;
            }

            stringBuilder.append(
                "$paramUrl.Add(\"" + parameterName + "\", \"" + parameterValue
                    + "\")")
                .append(System.lineSeparator());
            break;
          case IParameter.PARAM_MULTIPART_ATTR:
//            if (firstParamMultipart) {
//              this.hasParamMultipart = true;
//              stringBuilder.append(
//                  "$paramMultipart = [System.Net.Http.MultipartFormDataContent]::new()")
//                  .append(System.lineSeparator());
//              firstParamMultipart = false;
//            }
//
//            stringBuilder.append(parameterName + " --- " + parameterValue)
//                .append(System.lineSeparator());
            break;
          default:
            callbacks
                .printError(
                    "Please raise a new issue on https://github.com/AresS31/copy_as_powershell_requests.");
            break;
        }
      }
    }

    return stringBuilder;
  }
}
