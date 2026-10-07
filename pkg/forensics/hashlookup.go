package forensics

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type HashLookupResponse struct {
	FileName    string `json:"file-name"`
	ProductCode string `json:"product-code"`
	Source      string `json:"source"`
}

// CheckHashlookup يفحص الـ SHA256 مجاناً لمعرفة إذا كان الملف معروفا وشريعا (Whitelisting)
func CheckHashlookup(sha256 string) (bool, string) {
	url := fmt.Sprintf("https://hashlookup.circl.lu/lookup/sha256/%s", sha256)
	
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(url)
	if err != nil || resp.StatusCode != http.StatusOK {
		return false, ""
	}
	defer resp.Body.Close()

	var result HashLookupResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false, ""
	}

	if result.FileName != "" {
		return true, result.FileName
	}
	
	return true, "Known Safe Binary"
}
