package resource

func hasDuplicates(ss []string) bool {
	vm := map[string]int{}
	for _, v := range ss {
		if vm[v] == 0 {
			vm[v] = 1
		} else {
			return true
		}
	}
	return false
}
