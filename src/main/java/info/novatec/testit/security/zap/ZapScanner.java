package info.novatec.testit.security.zap;

import org.zaproxy.clientapi.core.Alert;

import java.util.List;

/**
 * The ZAProxy scanner.
 */
public interface ZapScanner {

    /**
     * Perform passive and active scanning for given baseUrl and scanPolicyName.
     *
     * @param baseUrl        base url to scan
     * @param scanPolicyName policy name for scan (may be null for default)
     * @return list of alerts occurred
     */
    List<Alert> completeScan ( String baseUrl, String scanPolicyName );

}