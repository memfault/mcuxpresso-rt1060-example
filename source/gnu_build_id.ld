/*
  Custom section to be included in the linker command file to support GNU build
  id.
*/

SECTIONS
{
    .note.gnu.build-id :
    {
        __start_gnu_build_id_start = .;
        KEEP(*(.note.gnu.build-id))
    }
}
INSERT AFTER .text;
