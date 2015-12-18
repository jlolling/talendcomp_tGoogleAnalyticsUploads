/**
 * Copyright 2015 Jan Lolling jan.lolling@gmail.com
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.jlo.talendcomp.google.gauploads;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.Reader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.log4j.Logger;

import com.google.api.client.auth.oauth2.Credential;
import com.google.api.client.extensions.java6.auth.oauth2.AuthorizationCodeInstalledApp;
import com.google.api.client.extensions.jetty.auth.oauth2.LocalServerReceiver;
import com.google.api.client.googleapis.auth.oauth2.GoogleAuthorizationCodeFlow;
import com.google.api.client.googleapis.auth.oauth2.GoogleClientSecrets;
import com.google.api.client.googleapis.auth.oauth2.GoogleCredential;
import com.google.api.client.googleapis.json.GoogleJsonError;
import com.google.api.client.googleapis.json.GoogleJsonResponseException;
import com.google.api.client.googleapis.media.MediaHttpUploader;
import com.google.api.client.googleapis.media.MediaHttpUploaderProgressListener;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpRequestInitializer;
import com.google.api.client.http.HttpResponseException;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.InputStreamContent;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.GenericJson;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.client.util.Clock;
import com.google.api.client.util.store.FileDataStoreFactory;
import com.google.api.services.analytics.Analytics;
import com.google.api.services.analytics.AnalyticsRequest;
import com.google.api.services.analytics.Analytics.Management.Uploads.UploadData;
import com.google.api.services.analytics.AnalyticsScopes;
import com.google.api.services.analytics.model.CustomDataSource;
import com.google.api.services.analytics.model.CustomDataSources;
import com.google.api.services.analytics.model.Upload;
import com.google.api.services.analytics.model.Uploads;

public class UploadHelper {

	private Logger logger = null;
	private static final Map<String, UploadHelper> clientCache = new HashMap<String, UploadHelper>();
	private final HttpTransport HTTP_TRANSPORT = new NetHttpTransport();
	private final JsonFactory JSON_FACTORY = new JacksonFactory();
	private File keyFile; // *.p12 key file is needed
	private String accountEmail;
	private String applicationName = null;
	private boolean useServiceAccount = true;
	private String credentialDataStoreDir = null;
	private String clientSecretFile = null;
	private int timeoutInSeconds = 120;
	private Analytics analyticsClient;
	private long timeMillisOffsetToPast = 10000;
	private List<Upload> listUploads;
	private List<CustomDataSource> listDataSources;
	private long mainWaitInterval = 2000;
	private long innerLoopWaitInterval = 500;
	private int maxRows = 0;
	private int currentIndex = 0;
	private String customDataSourceId;
	private String webPropertyId;
	private String accountId;
	
	public static void putIntoCache(String key, UploadHelper gam) {
		clientCache.put(key, gam);
	}
	
	public static UploadHelper getFromCache(String key) {
		return clientCache.get(key);
	}
	
	public void setApplicationName(String applicationName) {
		this.applicationName = applicationName;
	}

	public void setKeyFile(String file) {
		keyFile = new File(file);
	}

	public void setAccountEmail(String email) {
		accountEmail = email;
	}

	public void setTimeoutInSeconds(int timeoutInSeconds) {
		this.timeoutInSeconds = timeoutInSeconds;
	}
	
	public void initializeAnalyticsClient() throws Exception {
		// Authorization.
		final Credential credential;
		if (useServiceAccount) {
			credential = authorizeWithServiceAccount();
		} else {
			credential = authorizeWithClientSecret();
		}
		// Set up and return Google Analytics API client.
		analyticsClient = new Analytics.Builder(
			HTTP_TRANSPORT, 
			JSON_FACTORY, 
			new HttpRequestInitializer() {
				@Override
				public void initialize(final HttpRequest httpRequest) throws IOException {
					credential.initialize(httpRequest);
					httpRequest.setConnectTimeout(timeoutInSeconds * 1000);
					httpRequest.setReadTimeout(timeoutInSeconds * 1000);
				}
			})
			.setApplicationName(applicationName)
			.build();
	}
	
	private Credential authorizeWithServiceAccount() throws Exception {
		if (keyFile == null) {
			throw new Exception("KeyFile not set!");
		}
		if (keyFile.canRead() == false) {
			throw new IOException("keyFile:" + keyFile.getAbsolutePath()
					+ " is not readable");
		}
		if (accountEmail == null || accountEmail.isEmpty()) {
			throw new Exception("account email cannot be null or empty");
		}
		// Authorization.
		return new GoogleCredential.Builder()
				.setTransport(HTTP_TRANSPORT)
				.setJsonFactory(JSON_FACTORY)
				.setServiceAccountId(accountEmail)
				.setServiceAccountScopes(Arrays.asList(AnalyticsScopes.ANALYTICS))
				.setServiceAccountPrivateKeyFromP12File(keyFile)
				.setClock(new Clock() {
					@Override
					public long currentTimeMillis() {
						// we must be sure, that we are always in the past from Googles point of view
						// otherwise we get an "invalid_grant" error
						return System.currentTimeMillis() - timeMillisOffsetToPast;
					}
				})
				.build();
	}
	
	/**
	 * Authorizes the installed application to access user's protected YouTube
	 * data.
	 * 
	 * @param scopes
	 *            list of scopes needed to access general and analytic YouTube
	 *            info.
	 */
	private Credential authorizeWithClientSecret() throws Exception {
		if (clientSecretFile == null) {
			throw new IllegalStateException("client secret file is not set");
		}
		File secretFile = new File(clientSecretFile);
		if (secretFile.exists() == false) {
			throw new Exception("Client secret file:" + secretFile.getAbsolutePath() + " does not exists or is not readable.");
		}
		Reader reader = new FileReader(secretFile);
		// Load client secrets.
		GoogleClientSecrets clientSecrets = GoogleClientSecrets.load(JSON_FACTORY, reader);
		try {
			reader.close();
		} catch (Throwable e) {}
		// Checks that the defaults have been replaced (Default =
		// "Enter X here").
		if (clientSecrets.getDetails().getClientId().startsWith("Enter")
				|| clientSecrets.getDetails().getClientSecret()
						.startsWith("Enter ")) {
			throw new Exception("The client secret file does not contains the credentials. At first you have to pass the web based authorization process!");
		}
		credentialDataStoreDir = secretFile.getParent() + "/" + clientSecrets.getDetails().getClientId() + "/";
		File credentialDataStoreDirFile = new File(credentialDataStoreDir);             
		if (credentialDataStoreDirFile.exists() == false && credentialDataStoreDirFile.mkdirs() == false) {
			throw new Exception("Credentedial data dir does not exists or cannot created:" + credentialDataStoreDir);
		}
		FileDataStoreFactory fdsf = new FileDataStoreFactory(credentialDataStoreDirFile);
		// Set up authorization code flow.
		GoogleAuthorizationCodeFlow flow = new GoogleAuthorizationCodeFlow.Builder(
				HTTP_TRANSPORT, 
				JSON_FACTORY, 
				clientSecrets, 
				Arrays.asList(AnalyticsScopes.ANALYTICS))
			.setDataStoreFactory(fdsf)
			.setClock(new Clock() {
				@Override
				public long currentTimeMillis() {
					// we must be sure, that we are always in the past from Googles point of view
					// otherwise we get an "invalid_grant" error
					return System.currentTimeMillis() - timeMillisOffsetToPast;
				}
			})
			.build();
		// Authorize.
		return new AuthorizationCodeInstalledApp(
				flow,
				new LocalServerReceiver()).authorize(accountEmail);
	}

	public void reset() {
		listUploads = null;
		listDataSources = null;
		maxRows = 0;
		currentIndex = 0;
	}

	private void setMaxRows(int rows) {
		if (maxRows < rows) {
			maxRows = rows;
		}
	}
	
	public void setTimeOffsetMillisToPast(long timeMillisOffsetToPast) {
		this.timeMillisOffsetToPast = timeMillisOffsetToPast;
	}

	public boolean next() {
		return ++currentIndex <= maxRows;
	}
	
	public int getMaxRows() {
		return maxRows;
	}
	
	public int getCurrentIndex() {
		return currentIndex - 1;
	}
	
	public long getMainWaitInterval() {
		return mainWaitInterval;
	}

	public void setMainWaitInterval(long mainWaitInterval) {
		this.mainWaitInterval = mainWaitInterval;
	}

	public long getInnerLoopWaitInterval() {
		return innerLoopWaitInterval;
	}

	public void setInnerLoopWaitInterval(long innerLoopWaitInterval) {
		this.innerLoopWaitInterval = innerLoopWaitInterval;
	}
	
	private int maxRetriesInCaseOfErrors = 5;
	private int currentAttempt = 0;
	private int errorCode = 0;
	private String errorMessage = null;
	private boolean ignoreUserPermissionErrors = false;

	private com.google.api.client.json.GenericJson execute(AnalyticsRequest<?> request) throws IOException {
		com.google.api.client.json.GenericJson response = null;
		int waitTime = 1000;
		for (currentAttempt = 0; currentAttempt < maxRetriesInCaseOfErrors; currentAttempt++) {
			errorCode = 0;
			try {
				response = (GenericJson) request.execute();
				break;
			} catch (IOException ge) {
				boolean stopImmediately = false;
				boolean permissionError = false;
				warn("Got error:" + ge.getMessage());
				if (ge instanceof GoogleJsonResponseException) {
					GoogleJsonError gje = ((GoogleJsonResponseException) ge).getDetails();
					if (gje != null) {
						if (gje.getCode() != 500) {
							stopImmediately = true;
							if (gje.getMessage().toLowerCase().contains("permission")) {
								permissionError = true;
							}
						}
					}
				}
				if (stopImmediately) {
					if (permissionError && ignoreUserPermissionErrors) {
						info("Permission error ignored. Element skipped.");
						break;
					} else {
						throw ge; // it does not makes sense to repeat request which fails because of permissions
					}
				} else {
					if (ge instanceof HttpResponseException) {
						errorCode = ((HttpResponseException) ge).getStatusCode();
					}
					if (currentAttempt == (maxRetriesInCaseOfErrors - 1)) {
						error("All repetition of requests failed:" + ge.getMessage(), ge);
						throw ge;
					} else {
						// wait
						try {
							info("Retry request in " + waitTime + "ms");
							Thread.sleep(waitTime);
						} catch (InterruptedException ie) {}
						waitTime = waitTime * 2;
					}
				}
			}
		}
		try {
			Thread.sleep(innerLoopWaitInterval);
		} catch (InterruptedException e) {}
		return response;
	}

	public Upload startUpload(String filePath) throws Exception {
		if (accountId == null) {
			throw new IllegalStateException("Account-ID not set!");
		}
		if (webPropertyId == null) {
			throw new IllegalStateException("Web Property-ID not set!");
		}
		if (customDataSourceId == null) {
			throw new IllegalStateException("Custom Data Source ID not set!");
		}
		if (filePath == null || filePath.trim().isEmpty()) {
			throw new IllegalArgumentException("filePath cannot be null or empty");
		}
		File file = new File(filePath);
		if (file.canRead() == false) {
			throw new Exception("File:" + filePath + " cannot be read or does not exists!");
		}
		InputStreamContent mediaContent = new InputStreamContent(
				"application/octet-stream",
				new FileInputStream(file));
		mediaContent.setLength(file.length());
		UploadData request = analyticsClient
				.management()
				.uploads()
				.uploadData(accountId, webPropertyId, customDataSourceId, mediaContent);
		MediaHttpUploader uploader = request.getMediaHttpUploader();
	    uploader.setDirectUploadEnabled(false);
	    uploader.setProgressListener(new MediaHttpUploaderProgressListener() {
			
			@Override
			public void progressChanged(MediaHttpUploader uploader) throws IOException {
				System.out.println("File status: " + uploader.getUploadState());
				System.out.println("Bytes uploaded:" + uploader.getNumBytesUploaded());
			}
			
		});
	    return (Upload) execute(request);
	}
	
	public void collectUploads() throws Exception {
		if (accountId == null) {
			throw new IllegalStateException("Account-ID not set!");
		}
		if (webPropertyId == null) {
			throw new IllegalStateException("Web Property-ID not set!");
		}
		if (customDataSourceId == null) {
			throw new IllegalStateException("Custom Data Source ID not set!");
		}
		listUploads = new ArrayList<Upload>();
		Uploads reports = (Uploads) execute(
				analyticsClient
				.management()
				.uploads()
				.list(accountId, webPropertyId, customDataSourceId));
		if (reports != null && reports.getItems() != null) {
			for (Upload report : reports.getItems()) {
				listUploads.add(report);
			}
			setMaxRows(listUploads.size());
		}
	}
	
	public void collectCustomDataSources() throws Exception {
		if (accountId == null) {
			throw new IllegalStateException("Account-ID not set!");
		}
		if (webPropertyId == null) {
			throw new IllegalStateException("Web Property-ID not set!");
		}
		listDataSources = new ArrayList<CustomDataSource>();
		CustomDataSources dataSources = (CustomDataSources) execute(
				analyticsClient
				.management()
				.customDataSources()
				.list(accountId, webPropertyId));
		if (dataSources != null && dataSources.getItems() != null) {
			for (CustomDataSource ds : dataSources.getItems()) {
				listDataSources.add(ds);
			}
			setMaxRows(listDataSources.size());
		}
	}

	public boolean hasCurrentUpload() {
		if (listUploads != null) {
			return currentIndex <= listUploads.size();
		} else {
			return false;
		}
	}
	
	public Upload getCurrentUpload() {
		if (currentIndex == 0) {
			throw new IllegalStateException("Call next before!");
		}
		if (currentIndex <= listUploads.size()) {
			return listUploads.get(currentIndex - 1);
		} else {
			return null;
		}
	}

	public boolean hasCurrentCustomDataSource() {
		if (listDataSources != null) {
			return currentIndex <= listDataSources.size();
		} else {
			return false;
		}
	}
	
	public CustomDataSource getCurrentCustomDataSource() {
		if (currentIndex == 0) {
			throw new IllegalStateException("Call next before!");
		}
		if (currentIndex <= listDataSources.size()) {
			return listDataSources.get(currentIndex - 1);
		} else {
			return null;
		}
	}

	public void setCustomDataSourceId(String customDatasourceId) {
		this.customDataSourceId = customDatasourceId;
	}

	public String getWebPropertyId() {
		return webPropertyId;
	}

	public void setWebPropertyId(String webPropertyId) {
		if (webPropertyId == null || webPropertyId.trim().isEmpty()) {
			throw new IllegalArgumentException("webPropertyId cannot be null or empty.");
		}
		this.webPropertyId = webPropertyId;
	}

	public String getAccountId() {
		return accountId;
	}

	public void setAccountId(String accountId) {
		if (accountId == null || accountId.trim().isEmpty()) {
			throw new IllegalArgumentException("accountId cannot be null or empty.");
		}
		this.accountId = accountId;
	}
	
	public void setAccountId(Number accountId) {
		if (accountId == null) {
			throw new IllegalArgumentException("accountId cannot be null.");
		}
		this.accountId = Long.toString(accountId.longValue());
	}

	public boolean isUseServiceAccount() {
		return useServiceAccount;
	}

	public void setUseServiceAccount(boolean useServiceAccount) {
		this.useServiceAccount = useServiceAccount;
	}

	public String getClientSecretFile() {
		return clientSecretFile;
	}

	public void setClientSecretFile(String clientSecretFile) {
		this.clientSecretFile = clientSecretFile;
	}

	/**
	 * builds a separated String from the list entries
	 * @param list
	 * @param separator
	 * @return the chained strings
	 */
	public static String buildChain(List<String> list, String separator) {
		if (list == null || list.isEmpty()) {
			return null;
		}
		boolean firstLoop = true;
		StringBuilder sb = new StringBuilder();
		for (String s : list) {
			if (firstLoop) {
				firstLoop = false;
			} else {
				sb.append(separator);
			}
			sb.append(s);
		}
		return sb.toString();
	}

	public void info(String message) {
		if (logger != null) {
			logger.info(message);
		} else {
			System.out.println("INFO:" + message);
		}
	}
	
	public void debug(String message) {
		if (logger != null) {
			logger.debug(message);
		} else {
			System.out.println("DEBUG:" + message);
		}
	}

	public void warn(String message) {
		if (logger != null) {
			logger.warn(message);
		} else {
			System.err.println("WARN:" + message);
		}
	}

	public void error(String message, Exception e) {
		if (logger != null) {
			logger.error(message, e);
		} else {
			System.err.println("ERROR:" + message);
		}
	}

	public void setLogger(Logger logger) {
		this.logger = logger;
	}

	public int getErrorCode() {
		return errorCode;
	}

	public String getErrorMessage() {
		return errorMessage;
	}

	public void setInnerLoopWaitInterval(Number innerLoopWaitInterval) {
		if (innerLoopWaitInterval != null) {
			long value = innerLoopWaitInterval.longValue();
			if (value > 500l) {
				this.innerLoopWaitInterval = value;
			}
		}
	}
	
	public void setMaxRetriesInCaseOfErrors(Integer maxRetriesInCaseOfErrors) {
		if (maxRetriesInCaseOfErrors != null && maxRetriesInCaseOfErrors > 0) {
			this.maxRetriesInCaseOfErrors = maxRetriesInCaseOfErrors;
		}
	}

}
