import os
from fame.core.module import ProcessingModule
from fame.common.utils import tempdir
import subprocess
import tempfile
import magic

class Upx(ProcessingModule):
    name = "upx"
    description = "Extract files from upx packer."
    acts_on = "executable"

    def unpack(self, target, output):
        try:
            subprocess.call("(upx -d %s -o %s)" % (target, output), shell=True)
        except Exception as e:
            self.log('error', 'Could not extract {}'.format(target))
            return False
        return True

    def each(self, target):
        tmpdir = tempdir()
        f = magic.Magic(mime=False, uncompress=False)
        details = f.from_file(target)
        if details.find('UPX compressed') != -1:
            output = os.path.join(tmpdir, 'unpacked_upx_%s' % os.path.basename(target))
            r = self.unpack(target, output)
            if os.path.isfile(output) and r:
                self.add_extracted_file(output)
        else:
            return False
        return True
