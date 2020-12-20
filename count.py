import sys

if len(sys.argv) != 2:
	print("Usage: python count.py [input_file]")
	sys.exit()



fr = open(sys.argv[1], 'r')
fw = open('counted_' + sys.argv[1], 'w')


page_bag = {}

while True:
	rline = fr.readline()
	if not rline: break;
	item = rline.split(',')
	page = int(item[0])
	if not page in page_bag:
		page_bag[page] = 1
	else:
		page_bag[page] = page_bag[page] + 1
	

fr.close()

for key in page_bag.keys():
	wline = "%d,%d,\n" % (key, page_bag[key])
	fw.write(wline)

fw.close()
	
