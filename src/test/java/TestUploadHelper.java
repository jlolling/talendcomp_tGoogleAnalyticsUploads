import java.util.List;

import com.google.api.services.analytics.model.CustomDataSource;
import com.google.api.services.analytics.model.UnsampledReport;
import com.google.api.services.analytics.model.Upload;

import de.jlo.talendcomp.google.analytics.uploads.UploadHelper;

public class TestUploadHelper {

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		try {
//			testUpload();
			testListUploads();
//			testListDataSources();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	
	private static void printout(List<String> record) {
		boolean firstLoop = true;
		for (String s : record) {
			if (firstLoop) {
				firstLoop = false;
			} else {
				System.out.print("|");
			}
			System.out.print(s);
		}
		System.out.println();
	}
	
	private static UploadHelper getUploadHelper() throws Exception {
		UploadHelper gm = new UploadHelper();
		gm.setApplicationName("GATalendComp");

		gm.setAccountEmail("503880615382@developer.gserviceaccount.com");
		gm.setKeyFile("/Volumes/Data/Talend/testdata/ga/config/2bc309bb904201fcc6a443ff50a3d8aca9c0a12c-privatekey.p12");
		gm.setUseServiceAccount(true);
//		gm.setAccountEmail("422451649636@developer.gserviceaccount.com");
//		gm.setKeyFile("/Volumes/Data/Talend/testdata/ga/config/af21f07c84b14af09c18837c5a385f8252cc9439-privatekey.p12");
		gm.setTimeOffsetMillisToPast(10000);
		gm.setTimeoutInSeconds(240);
		gm.reset();
		System.out.println("initialize client....");
		gm.initializeAnalyticsClient();
		return gm;
	}

	public static void testListUploads() throws Exception {

		UploadHelper gm = getUploadHelper();

		try {
			gm.setAccountId("31730276");
			gm.setWebPropertyId("UA-31730276-1");
			gm.setCustomDataSourceId("BVwls0MqSKGYlvXEDGTUQg");
			System.out.println("List uploads....");
			gm.collectUploads();
			while (gm.next()) {
				Upload up = gm.getCurrentUpload();
				System.out.println("ID=" + up.getId());
				System.out.println("Status=" + up.getStatus());
				System.out.println("Account=" + up.getAccountId());
				System.out.println("Errors=" + UploadHelper.buildChain(up.getErrors(),"|"));
				System.out.println("DataSource=" + up.getCustomDataSourceId());
				System.out.println();
			}
			System.out.println("Done.");
		} catch (Exception e1) {
			e1.printStackTrace();
		}
	}

	public static void testListDataSources() throws Exception {

		UploadHelper gm = getUploadHelper();

		try {
			gm.setAccountId("31730276");
			gm.setWebPropertyId("UA-31730276-1");
			System.out.println("List data sources....");
			gm.collectCustomDataSources();
			while (gm.next()) {
				if (gm.hasCurrentCustomDataSource()) {
					CustomDataSource ds = gm.getCurrentCustomDataSource();
					System.out.println("ID=" + ds.getId());
					System.out.println("Name=" + ds.getName());
					System.out.println("Description=" + ds.getDescription());
					System.out.println("Account=" + ds.getAccountId());
					System.out.println("WebPropertyId=" + ds.getWebPropertyId());
					System.out.println("Import behavior=" + ds.getImportBehavior());
					System.out.println("Type=" + ds.getType());
					System.out.println("UploadType=" + ds.getUploadType());
					System.out.println("Created at=" + ds.getCreated());
					System.out.println("Updated at=" + ds.getUpdated());
					System.out.println("Profiles linked=" + UploadHelper.buildChain(ds.getProfilesLinked(),"|"));
					System.out.println("Unknown keys=" + ds.getUnknownKeys());
					System.out.println();
				} else {
					break;
				}
			}
			System.out.println("Done.");
		} catch (Exception e1) {
			e1.printStackTrace();
		}
	}
	
	public static void testUpload() throws Exception {
		UploadHelper gm = getUploadHelper();
		Upload currentUpload = null;
		try {
			gm.setAccountId("31730276");
			gm.setWebPropertyId("UA-31730276-1");
			gm.setCustomDataSourceId("BVwls0MqSKGYlvXEDGTUQg");
			System.out.println("Upload....");
			currentUpload = gm.startUpload("/Volumes/Data/Talend/testdata/ga/uploads/Test_campaign_dataset.csv");
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}
