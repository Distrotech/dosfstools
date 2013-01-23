/*
   Filename:     mkdosfs.c
   Version:      2.x
   Author:       Dave Hudson
   Started:      24th August 1994
   Last Updated: 25th September 2008
   Updated by:   Debian
   Target O/S:   Linux (2.x)

   Description: Utility to allow a FAT/MS-DOS filesystem to be created
   under Linux.  A lot of the basic structure of this program has been
   borrowed from Remy Card's "mke2fs" code.

   As far as possible the aim here is to make the "mkdosfs" command
   look almost identical to the other Linux filesystem make utilities,
   e.g., bad blocks are still specified as blocks, not sectors, but when
   it comes down to it, DOS is tied to the idea of a sector (512 bytes
   as a rule), and not the block. For example the boot block does not
   occupy a full cluster.

   Fixes/additions May 1998 by Roman Hodek
   <Roman.Hodek@informatik.uni-erlangen.de>:
   - Atari format support
   - New options -A, -S, -C
   - Support for filesystems > 2GB
   - FAT32 support

   Fixes/additions June 2003 by Sam Bingner
   <sam@bingner.com>:
   - Add -B option to read in bootcode from a file
   - Write BIOS drive number so that FS can properly boot

   Fixes/additions September 2008 by Michael Shell
   <www.michaelshell.org>
   - Improve/fix auto/default start sector (i.e., hidden sectors) value
   - Improve/fix auto/default number of heads value
   - Fix potential ordering bugs with floppy geometry fields on big
     endian machines
   - Fix invalid backup boot sector location under FAT32 when
     number of reserved sectors is 2
   - Improve option acquisition and range checking
   - Improve verbose summary data
   - Add -d option to allow user to specify BIOS drive number
   - Add -H option to allow user to specify number of heads
   - Add -M option to allow user to specify media descriptor
   - Add -t option to allow user to specify number of sectors per track
   - Add -T option to allow user to specify hardware sector size,
     default to the hardware sector size given by kernel
   - Allow -c to work with -l, not just one or the other
   - Support the backup FSInfo sector of FAT32 filesystems
   - Improve boot loader template import with sanity checks and allow
     operation with mismatched sector sizes
   - Source cleanup with GNU indent --no-tabs
   - Man page additions, updates, corrections and improvements

   Copying: Copyright 1993, 1994 David Hudson (dave@humbug.demon.co.uk)

   Portions copyright 1992, 1993 Remy Card (card@masi.ibp.fr)
   and 1991 Linus Torvalds (torvalds@klaava.helsinki.fi)

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA. */


/* Include the header files */

#include "../version.h"

#include <fcntl.h>
#include <linux/hdreg.h>
#include <linux/fs.h>
#include <linux/fd.h>
#include <endian.h>
#include <mntent.h>
#include <signal.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>

#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 0)
# define __KERNEL__
# include <asm/types.h>
# undef __KERNEL__
#endif

#if __BYTE_ORDER == __BIG_ENDIAN

#include <asm/byteorder.h>
#ifdef __le16_to_cpu
/* ++roman: 2.1 kernel headers define these functions, they're probably more
 * efficient then coding the swaps machine-independently. */
/* CF_LE = convert from little endian, CT_LE = convert to little endian */
/* unaligned accesses will be trapped and properly handled by the kernel */
#define CF_LE_W __le16_to_cpu
#define CF_LE_L __le32_to_cpu
#define CT_LE_W __cpu_to_le16
#define CT_LE_L __cpu_to_le32
#else
/* note that these guys won't work for negative values */
#define CF_LE_W(v) ((((v) & 0xff) << 8) | (((v) >> 8) & 0xff))
#define CF_LE_L(v) (((unsigned)(v)>>24) | (((unsigned)(v)>>8)&0xff00) | \
               (((unsigned)(v)<<8)&0xff0000) | ((unsigned)(v)<<24))
#define CT_LE_W(v) CF_LE_W(v)
#define CT_LE_L(v) CF_LE_L(v)
#endif /* defined(__le16_to_cpu) */

#else
/* for a little endian machine, no need to reorder */
#define CF_LE_W(v) (v)
#define CF_LE_L(v) (v)
#define CT_LE_W(v) (v)
#define CT_LE_L(v) (v)

#endif /* __BIG_ENDIAN */


/* Constant definitions */
#define TRUE 1  /* Boolean constants */
#define FALSE 0

#define TEST_BUFFER_BLOCKS 16
#define DEFAULT_HW_SECTOR_SIZE 512 /* default hardware sector size */


/* Macro definitions */

/* Report a failure message and return a failure error code */
#define die( str ) fatal_error( "%s: " str "\n" )

/* Mark cluster which has the given hardware sector in the FAT as bad */
#define mark_hw_sector_bad( hw_sector ) mark_FAT_hw_sector( hw_sector, FAT_BAD )

/* Compute ceil(a/b) , i.e., if any remainder, round up */
inline int
cdiv (int a, int b)
{
  return (a + b - 1) / b;
}

/* MS-DOS filesystem structures -- I included them here instead of
   including linux/msdos_fs.h since that doesn't include some fields we
   need */
#define ATTR_RO      1          /* read-only */
#define ATTR_HIDDEN  2          /* hidden */
#define ATTR_SYS     4          /* system */
#define ATTR_VOLUME  8          /* volume label */
#define ATTR_DIR     16         /* directory */
#define ATTR_ARCH    32         /* archived */

#define ATTR_NONE    0          /* no attribute bits */
/* attribute bits that are copied "as is" */
#define ATTR_UNUSED  (ATTR_VOLUME | ATTR_ARCH | ATTR_SYS | ATTR_HIDDEN)

/* FAT values */
#define FAT_EOF      (atari_format ? 0x0fffffff : 0x0ffffff8)
#define FAT_BAD      0x0ffffff7

#define MSDOS_EXT_SIGN  0x29    /* extended boot sector signature */
#define HD_DRIVE_NUMBER 0x80    /* first hard drive BIOS device number */
#define FD_DRIVE_NUMBER 0x00    /* first floppy drive BIOS device number */
#define MSDOS_FAT12_SIGN "FAT12   "     /* FAT12 filesystem signature */
#define MSDOS_FAT16_SIGN "FAT16   "     /* FAT16 filesystem signature */
#define MSDOS_FAT32_SIGN "FAT32   "     /* FAT32 filesystem signature */

#define BOOT_SIGN 0xAA55        /* Boot sector magic number */

#define MAX_CLUST_12    ((1 << 12) - 16)
#define MAX_CLUST_16    ((1 << 16) - 16)
#define MIN_CLUST_32    65529
/* M$ says the high 4 bits of a FAT32 FAT entry are reserved and don't belong
 * to the cluster number. So the max. cluster# is based on 2^28 */
#define MAX_CLUST_32    ((1 << 28) - 16)

#define FAT12_THRESHOLD 4085

#define OLDGEMDOS_MAX_SECTORS   32765
#define GEMDOS_MAX_SECTORS      65531
#define GEMDOS_MAX_SECTOR_SIZE  (16*1024)

#define FSINFO_SECTOR 1  /* FSINFO sector number to use for FAT32 */
                         /* note: if this is not one, other code may need to be changed */
                         /* (e.g., template copy, backup_boot sector location, etc.)*/

#define BOOTCODE_SIZE           448
#define BOOTCODE_FAT32_SIZE     420

#define BOOT_TEMPLATE_SIZE      0xFFFF  /* maximum number of boot code template bytes */

/* __attribute__ ((packed)) is used on all structures to make gcc ignore any
 * alignments */
struct msdos_volume_info
{
  __u8 drive_number;            /* BIOS drive number */
  __u8 RESERVED;                /* unused */
  __u8 ext_boot_sign;           /* 0x29 if fields below exist (DOS 3.3+) */
  __u8 volume_id[4];            /* volume ID number */
  __u8 volume_label[11];        /* volume label */
  __u8 fs_type[8];              /* typically FAT12 or FAT16 */
} __attribute__ ((packed));

struct msdos_boot_sector
{
  __u8 boot_jump[3];            /* boot strap short or near jump */
  __u8 system_id[8];            /* name - can be used to special case
                                   partition manager volumes */
  __u8 sector_size[2];          /* bytes per logical sector */
  __u8 cluster_size;            /* sectors/cluster */
  __u16 reserved;               /* reserved sectors */
  __u8 fats;                    /* number of FATs */
  __u8 dir_entries[2];          /* root directory entries */
  __u8 sectors[2];              /* number of sectors */
  __u8 media;                   /* media code */
  __u16 fat_length;             /* sectors/FAT */
  __u16 secs_track;             /* sectors per track */
  __u16 heads;                  /* number of heads */
  __u32 hidden;                 /* hidden sectors */
  __u32 total_sect;             /* number of sectors (if sectors == 0) */
  union
  {
    struct
    {
      struct msdos_volume_info vi;
      __u8 boot_code[BOOTCODE_SIZE];
    } __attribute__ ((packed)) _oldfat;
    struct
    {
      __u32 fat32_length;       /* sectors/FAT */
      __u16 flags;              /* bit 8: fat mirroring, low 4: active fat */
      __u8 version[2];          /* major, minor filesystem version */
      __u32 root_cluster;       /* first cluster in root directory */
      __u16 info_sector;        /* filesystem info sector */
      __u16 backup_boot;        /* backup boot sector */
      __u16 reserved2[6];       /* unused */
      struct msdos_volume_info vi;
      __u8 boot_code[BOOTCODE_FAT32_SIZE];
    } __attribute__ ((packed)) _fat32;
  } __attribute__ ((packed)) fstype;
  __u16 boot_sign;
} __attribute__ ((packed));
#define fat32   fstype._fat32
#define oldfat  fstype._oldfat

struct fat32_fsinfo
{
  __u32 reserved1;              /* nothing as far as I can tell */
  __u32 signature;              /* 0x61417272L */
  __u32 free_clusters;          /* free cluster count. -1 if unknown */
  __u32 next_cluster;           /* most recently allocated cluster
                                   unused under Linux. */
  __u32 reserved2[4];
};

struct msdos_dir_entry
{
  char name[8], ext[3];         /* name and extension */
  __u8 attr;                    /* attribute bits */
  __u8 lcase;                   /* case for base and extension */
  __u8 ctime_ms;                /* creation time, milliseconds */
  __u16 ctime;                  /* creation time */
  __u16 cdate;                  /* creation date */
  __u16 adate;                  /* last access date */
  __u16 starthi;                /* high 16 bits of first cl. (FAT32) */
  __u16 time, date, start;      /* time, date and first cluster */
  __u32 size;                   /* file size (in bytes) */
} __attribute__ ((packed));


/* The "boot code" we put into the filesystem... it writes a message and
   tells the user to try again */
char dummy_boot_jump[3] = { 0xeb, 0x3c, 0x90 };

char dummy_boot_jump_m68k[2] = { 0x60, 0x1c };

#define MSG_OFFSET_OFFSET 3
char dummy_boot_code[BOOTCODE_SIZE] = "\x0e"    /* push cs */
  "\x1f"                        /* pop ds */
  "\xbe\x5b\x7c"                /* mov si, offset message_txt */
  /* write_msg: */
  "\xac"                        /* lodsb */
  "\x22\xc0"                    /* and al, al */
  "\x74\x0b"                    /* jz key_press */
  "\x56"                        /* push si */
  "\xb4\x0e"                    /* mov ah, 0eh */
  "\xbb\x07\x00"                /* mov bx, 0007h */
  "\xcd\x10"                    /* int 10h */
  "\x5e"                        /* pop si */
  "\xeb\xf0"                    /* jmp write_msg */
  /* key_press: */
  "\x32\xe4"                    /* xor ah, ah */
  "\xcd\x16"                    /* int 16h */
  "\xcd\x19"                    /* int 19h */
  "\xeb\xfe"                    /* foo: jmp foo */
  /* message_txt: */
  "This is not a bootable disk.  Please insert a bootable floppy and\r\n" "press any key to try again ... \r\n";

#define MESSAGE_OFFSET 29       /* Offset of message in above code */


/* Global variables */

static char *program_name = "mkdosfs";  /* name of the program */
static char *device_name = NULL;        /* name of the device on which to create the filesystem */
static int atari_format = 0;    /* use Atari variation of MS-DOS FS format flag */
static int check = FALSE;       /* default to no readability checking */
static int verbose = 0;         /* default to verbose mode off */
static long volume_id;          /* volume ID number */
static time_t create_time;      /* creation time */
static char volume_name[] = "           ";      /* volume name */
static unsigned long long blocks;       /* number of blocks in filesystem */
static int sector_size = 0;     /* size of a logical sector */
static int sector_size_set = 0; /* user selected logical sector size flag */
static int hw_sector_size = 0;  /* size of a hardware sector */
static int hw_sector_size_user = 0;     /* user given size of a hardware sector */
static int hw_sector_size_set = 0;      /* user selected hardware sector size flag */
static int backup_boot = 0;     /* sector number of backup boot sector */
static int reserved_sectors = 0;        /* number of reserved sectors */
static int badblocks = 0;       /* number of bad blocks in the filesystem */
static int nr_fats = 2;         /* default number of FATs to produce */
static int size_fat = 0;        /* size in bits of FAT entries */
static int size_fat_by_user = 0;        /* user selected FAT size flag */
static int dev = -1;            /* FS block device file handle */
static int bios_drive_number = 0;       /* BIOS physical drive number */
static int use_bios_drive_number = 0;   /* user specified a BIOS physical drive number flag */
static int media_descriptor = 0;        /* user given media descriptor value */
static int use_media_descriptor = 0;    /* user specified media descriptor flag */
static int ignore_full_disk = 0;        /* ignore safeguard about 'full' disk devices */
static int is_full_disk = 0;    /* full disk device flag */
static off_t currently_testing = 0;     /* block currently being tested (if autodetect bad blocks) */
static struct msdos_boot_sector bs;     /* boot sector data */
static int start_data_hw_sector;   /* hardware sector number for the start of the data area */
static int start_data_block;    /* block number for the start of the data area */
static unsigned char *fat;      /* file allocation table */
static unsigned char *info_sector;      /* FAT32 info sector */
static struct msdos_dir_entry *root_dir;        /* root directory */
static int size_root_dir;       /* size of the root directory in bytes */
static int sectors_per_cluster = 0;     /* number of sectors per disk cluster */
static int root_dir_entries = 0;        /* number of root directory entries */
static char *blank_sector;      /* blank sector - all zeros */
static int number_of_heads = 0; /* number of heads value specified by user */
static int use_number_of_heads = 0;     /* user specified number of heads flag */
static unsigned int hidden_sectors = 0; /* number of hidden sectors */
static int use_hidden_sectors = 0;      /* user specified hidden sector count flag */
static int sectors_per_track = 0;       /* number of sectors per track */
static int use_sectors_per_track = 0;   /* user specified sectors per track flag */
static long int acquired_option_val = 0;        /* for strtol option returned values */
static char *template_boot_code;        /* variable to store template sectors in */
static int use_template = 0;    /* user specified a boot code template file flag */
static int template_size = 0;   /* size of user template file */
static int template_fat_type = 0;       /* template file FAT type - 16, 32 */
static int template_sector_size = 0;    /* sector size of user template file */
static int template_fsinfo_sector = 0;  /* template fsinfo sector location */
static int template_backup_sector = 0;  /* template backup boot sector location */
static int template_reserved_sectors = 0;       /* template number of reserved sectors */
static int template_sectors = 0;        /* template number of sectors */
static int template_sectors_can_copy = 0;       /* number of sectors we can safely copy from template */
static int lesser_sector_size = 0;      /* lesser number of bytes per sector between template and filesystem */
static int current_sector = 0;  /* current sector for copying from template */

/* Function prototype definitions */
static void fatal_error (const char *fmt_string) __attribute__ ((noreturn));
static void mark_FAT_cluster (int cluster, unsigned int value);
static void mark_FAT_hw_sector (int hw_sector, unsigned int value);
static long do_check (char *buffer, int try, off_t current_block);
static void alarm_intr (int alnum);
static void check_blocks (void);
static void get_list_blocks (char *filename);
static int valid_offset (int fd, loff_t offset);
static unsigned long long count_blocks (char *filename);
static void check_mount (char *device_name);
static void establish_params (int device_num, int size);
static void setup_tables (void);
static void write_tables (void);


/* The function implementations */

/* Handle the reporting of fatal errors. */
static void
fatal_error (const char *fmt_string)
{
  fprintf (stderr, fmt_string, program_name, device_name);
  exit (1); /* The error exit code is 1! */
}


/* Mark the specified cluster as having a particular value */
static void
mark_FAT_cluster (int cluster, unsigned int value)
{
  switch (size_fat)
    {
    case 12:
      value &= 0x0fff;
      if (((cluster * 3) & 0x1) == 0)
        {
          fat[3 * cluster / 2] = (unsigned char) (value & 0x00ff);
          fat[(3 * cluster / 2) + 1] = (unsigned char) ((fat[(3 * cluster / 2) + 1] & 0x00f0) | ((value & 0x0f00) >> 8));
        }
      else
        {
          fat[3 * cluster / 2] = (unsigned char) ((fat[3 * cluster / 2] & 0x000f) | ((value & 0x000f) << 4));
          fat[(3 * cluster / 2) + 1] = (unsigned char) ((value & 0x0ff0) >> 4);
        }
      break;

    case 16:
      value &= 0xffff;
      fat[2 * cluster] = (unsigned char) (value & 0x00ff);
      fat[(2 * cluster) + 1] = (unsigned char) (value >> 8);
      break;

    case 32:
      value &= 0xfffffff;
      fat[4 * cluster] = (unsigned char) (value & 0x000000ff);
      fat[(4 * cluster) + 1] = (unsigned char) ((value & 0x0000ff00) >> 8);
      fat[(4 * cluster) + 2] = (unsigned char) ((value & 0x00ff0000) >> 16);
      fat[(4 * cluster) + 3] = (unsigned char) ((value & 0xff000000) >> 24);
      break;

    default:
      die ("Bad FAT size (not 12, 16, or 32).");
    }
}


/* Mark the cluster that contains the specified hardware sector as having
   a particular value in its FAT entry */
static void
mark_FAT_hw_sector (int hw_sector, unsigned int value)
{
  int cluster;

  cluster = (hw_sector - start_data_hw_sector) / (int) (bs.cluster_size) / (sector_size / hw_sector_size);
  if (cluster < 0)
    die ("Invalid cluster number in mark_FAT_hw_sector: probably bug!");

  mark_FAT_cluster (cluster, value);
}


/* Perform a test on a block.  Return the number of blocks that could be read successfully */
static long
do_check (char *buffer, int try, off_t current_block)
{
  long got;

  if (lseek (dev, current_block * BLOCK_SIZE, SEEK_SET) /* Seek to the correct location */
      != current_block * BLOCK_SIZE)
    die ("Seek failed during testing for blocks.");

  got = read (dev, buffer, try * BLOCK_SIZE);   /* Try reading! */
  if (got < 0)
    got = 0;

  if (got & (BLOCK_SIZE - 1))
    fprintf (stderr, "Unexpected values in do_check: probably bugs.\n");
  got /= BLOCK_SIZE;

  return got;
}


/* Alarm clock handler - display the status of the quest for bad blocks!
   Then retrigger the alarm for five seconds later (so we can come here again) */
static void
alarm_intr (int alnum)
{
  if (currently_testing >= blocks)
    return;

  signal (SIGALRM, alarm_intr);
  alarm (5);
  if (!currently_testing)
    return;

  printf ("%lld... ", (unsigned long long) currently_testing);
  fflush (stdout);
}


/* search for bad blocks */
static void
check_blocks (void)
{
  int try, got;
  int i;
  static char blkbuf[BLOCK_SIZE * TEST_BUFFER_BLOCKS];

  if (verbose)
    {
      printf ("Searching for bad blocks ");
      fflush (stdout);
    }
  currently_testing = 0;
  if (verbose)
    {
      signal (SIGALRM, alarm_intr);
      alarm (5);
    }
  try = TEST_BUFFER_BLOCKS;
  while (currently_testing < blocks)
    {
      if (currently_testing + try > blocks)
        try = blocks - currently_testing;
      got = do_check (blkbuf, try, currently_testing);
      currently_testing += got;
      if (got == try)
        {
          try = TEST_BUFFER_BLOCKS;
          continue;
        }
      else
        try = 1;
      if (currently_testing < start_data_block)
        die ("Bad blocks before data-area: cannot make fs.");

      for (i = 0; i < (BLOCK_SIZE / hw_sector_size); i++)       /* Mark all of the sectors in the block as bad */
        mark_hw_sector_bad (currently_testing * (BLOCK_SIZE / hw_sector_size) + i);
      badblocks++;
      currently_testing++;
    }

  if (verbose)
    printf ("\n");

  if (badblocks)
    printf ("%d bad block%s.\n", badblocks, (badblocks > 1) ? "s" : "");
}


/* get list of bad blocks */
static void
get_list_blocks (char *filename)
{
  int i;
  FILE *listfile;
  unsigned long blockno;

  listfile = fopen (filename, "r");
  if (listfile == (FILE *) NULL)
    die ("Can't open file of bad blocks.");

  while (!feof (listfile))
    {
      fscanf (listfile, "%ld\n", &blockno);
      /* Mark all of the hardware sectors in the block as bad */
      for (i = 0; i < (BLOCK_SIZE / hw_sector_size); i++)
        mark_hw_sector_bad (blockno * (BLOCK_SIZE / hw_sector_size) + i);
      badblocks++;
    }
  fclose (listfile);

  if (badblocks)
    printf ("%d bad block%s.\n", badblocks, (badblocks > 1) ? "s" : "");
}


/* Given a file descriptor and an offset, check whether the offset is a valid
   offset for the file - return FALSE if it isn't valid or TRUE if it is */
static int
valid_offset (int fd, loff_t offset)
{
  char ch;

  if (lseek (fd, offset, SEEK_SET) < 0)
    return FALSE;
  if (read (fd, &ch, 1) < 1)
    return FALSE;
  return TRUE;
}


/* Given a filename, look to see how many blocks of BLOCK_SIZE are present,
   returning the answer */
static unsigned long long
count_blocks (char *filename)
{
  off_t high, low;
  int fd;

  if ((fd = open (filename, O_RDONLY)) < 0)
    {
      perror (filename);
      exit (1);
    }

  /* first try SEEK_END, which should work on most devices nowadays */
  if ((low = lseek (fd, 0, SEEK_END)) <= 0)
    {
      low = 0;
      for (high = 1; valid_offset (fd, high); high *= 2)
        low = high;
      while (low < high - 1)
        {
          const loff_t mid = (low + high) / 2;
          if (valid_offset (fd, mid))
            low = mid;
          else
            high = mid;
        }
      ++low;
    }

  close (fd);
  return low / BLOCK_SIZE;
}


/* Check to see if the specified device is currently mounted - abort if it is */
static void
check_mount (char *device_name)
{
  FILE *f;
  struct mntent *mnt;

  if ((f = setmntent (MOUNTED, "r")) == NULL)
    return;
  while ((mnt = getmntent (f)) != NULL)
    if (strcmp (device_name, mnt->mnt_fsname) == 0)
      die ("%s contains a mounted file system.");
  endmntent (f);
}


/* Establish the geometry and media parameters for the device */
static void
establish_params (int device_num, int size)
{
  long loop_size;
  struct hd_geometry geometry;
  struct floppy_struct param;

  bs.hidden = 0; /* default to zero, we'll adjust this as we go */

  if ((0 == device_num) || ((device_num & 0xff00) == 0x0200))
    /* file image or floppy disk */
    {
      if (0 == device_num)
        {
          param.size = size / 512;
          switch (param.size)
            {
            case 720:
              param.sect = 9;
              param.head = 2;
              break;
            case 1440:
              param.sect = 9;
              param.head = 2;
              break;
            case 2400:
              param.sect = 15;
              param.head = 2;
              break;
            case 2880:
              param.sect = 18;
              param.head = 2;
              break;
            case 5760:
              param.sect = 36;
              param.head = 2;
              break;
            default:
              /* fake values */
              param.sect = 32;
              param.head = 64;
              break;
            }

        }
      else /* is a floppy diskette */
        {
          if (ioctl (dev, FDGETPRM, &param))    /*  Can we get the diskette geometry? */
            die ("Unable to get diskette geometry for '%s'.");
        }
      bs.secs_track = CT_LE_W (param.sect);     /*  Set up the geometry information */
      bs.heads = CT_LE_W (param.head);
      switch (param.size)      /*  Set up the media descriptor byte */
        {
        case 720:              /* 5.25", 2, 9, 40 - 360K */
          bs.media = (char) 0xfd;
          bs.cluster_size = (char) 2;
          bs.dir_entries[0] = (char) 112;
          bs.dir_entries[1] = (char) 0;
          break;

        case 1440:             /* 3.5", 2, 9, 80 - 720K */
          bs.media = (char) 0xf9;
          bs.cluster_size = (char) 2;
          bs.dir_entries[0] = (char) 112;
          bs.dir_entries[1] = (char) 0;
          break;

        case 2400:             /* 5.25", 2, 15, 80 - 1200K */
          bs.media = (char) 0xf9;
          bs.cluster_size = (char) (atari_format ? 2 : 1);
          bs.dir_entries[0] = (char) 224;
          bs.dir_entries[1] = (char) 0;
          break;

        case 5760:             /* 3.5", 2, 36, 80 - 2880K */
          bs.media = (char) 0xf0;
          bs.cluster_size = (char) 2;
          bs.dir_entries[0] = (char) 224;
          bs.dir_entries[1] = (char) 0;
          break;

        case 2880:             /* 3.5", 2, 18, 80 - 1440K */
        floppy_default:
          bs.media = (char) 0xf0;
          bs.cluster_size = (char) (atari_format ? 2 : 1);
          bs.dir_entries[0] = (char) 224;
          bs.dir_entries[1] = (char) 0;
          break;

        default:               /* Anything else */
          if (0 == device_num)
            goto def_hd_params;
          else
            goto floppy_default;
        }
    }
  else if ((device_num & 0xff00) == 0x0700)     /* This is a loop device */
    {
      if (ioctl (dev, BLKGETSIZE, &loop_size))
        die ("Unable to get loop device size.");

      switch (loop_size)       /* Assuming the loop device -> floppy later */
        {
        case 720:              /* 5.25", 2, 9, 40 - 360K */
          bs.secs_track = CT_LE_W (9);
          bs.heads = CT_LE_W (2);
          bs.media = (char) 0xfd;
          bs.cluster_size = (char) 2;
          bs.dir_entries[0] = (char) 112;
          bs.dir_entries[1] = (char) 0;
          break;

        case 1440:             /* 3.5", 2, 9, 80 - 720K */
          bs.secs_track = CT_LE_W (9);
          bs.heads = CT_LE_W (2);
          bs.media = (char) 0xf9;
          bs.cluster_size = (char) 2;
          bs.dir_entries[0] = (char) 112;
          bs.dir_entries[1] = (char) 0;
          break;

        case 2400:             /* 5.25", 2, 15, 80 - 1200K */
          bs.secs_track = CT_LE_W (15);
          bs.heads = CT_LE_W (2);
          bs.media = (char) 0xf9;
          bs.cluster_size = (char) (atari_format ? 2 : 1);
          bs.dir_entries[0] = (char) 224;
          bs.dir_entries[1] = (char) 0;
          break;

        case 5760:             /* 3.5", 2, 36, 80 - 2880K */
          bs.secs_track = CT_LE_W (36);
          bs.heads = CT_LE_W (2);
          bs.media = (char) 0xf0;
          bs.cluster_size = (char) 2;
          bs.dir_entries[0] = (char) 224;
          bs.dir_entries[1] = (char) 0;
          break;

        case 2880:             /* 3.5", 2, 18, 80 - 1440K */
          bs.secs_track = CT_LE_W (18);
          bs.heads = CT_LE_W (2);
          bs.media = (char) 0xf0;
          bs.cluster_size = (char) (atari_format ? 2 : 1);
          bs.dir_entries[0] = (char) 224;
          bs.dir_entries[1] = (char) 0;
          break;

        default:               /* Anything else: default hd setup */
          fprintf (stderr, "Loop device does not match a floppy size, using default hd params.\n");
          bs.secs_track = CT_LE_W (63); /* these are fake values */
          bs.heads = CT_LE_W (255);
          bs.hidden = CT_LE_L (63);
          goto def_hd_params;
        }
    }
  else
    /* Must be a hard disk then! */
    {
      /* Can we get the kernel's lies about drive geometry?
       * If not, our job becomes real easy - we just go ahead and make
       * this stuff up right out of the blue.
       */
      if (ioctl (dev, HDIO_GETGEO, &geometry))
        {
          fprintf (stderr, "Unable to get drive geometry, using default 255/63.\n");
          bs.secs_track = CT_LE_W (63);
          bs.heads = CT_LE_W (255);
          bs.hidden = CT_LE_L (63);
        }
      else
        {
          /* Lies, tell me sweet little lies ...
           * Mark Twain said that there are three kinds of lies - lies,
           * damn lies, and statistics. There are a lot more where drive
           * geometry is concerned.
           * 
           * There has been a long standing problem with the issue of drive
           * geometry. As hard drives became ever larger, one geometry field
           * after another became too small and various short-sighted workarounds
           * along the lines of multiple layers of "lies" about the nature of the
           * "true" geometry were implemented which created ever more insanity.
           * The standard line from kernel developers is "Don't worry about it,
           * it's all fake anyway". That may be true, but some lies will work
           * while others won't. A case in point is here with respect to the
           * number of drive heads. As a boot loader will be using the BIOS
           * to access the drive, we want to know what the BIOS' lies are and
           * use those. The problem is that the Linux and FreeBSD folks never
           * bothered to provide a means for the kernel to record the BIOS'
           * lies at boot time (well, this is not completely true as 2.6.5 and
           * later do provide this information for the boot drive in the sys
           * filesystem if compiled with CONFIG_EDD, but we can't rely on this)
           * and to present them to user applications later when needed - especially
           * for those disk administration applications that need to know. And
           * mkdosfs needs to know. As it is, the kernel pretty much makes up its
           * own lies about the drive geometry. So, what to do?
           *
           * The BIOS size limitations (without INT 13 extensions) are 1024
           * cylinders, 255 heads and 63 sectors per track. With today's hard
           * drives it is almost always the case that the BIOS will be using
           * 255 heads. However, what of the small drives? Does the BIOS remap
           * every drive's geometry to 255 heads or just those over 8GB?
           *
           * For reference, the kernel's data structure for hd_geometry is
           * typically:
           * struct hd_geometry {
           * unsigned char heads;
           * unsigned char sectors;
           * unsigned short cylinders;
           * unsigned long start;};
           *
           * On my machine for a 120MB LS120 drive, the kernel's (2.6.25.4) lie
           * is 963 cylinders, 8 heads and 32 sectors per track. For my 100GB
           * Maxtor, its story is 65535 cylinders, 16 heads, and 63 sectors per
           * track. This latter head value will not allow Windows 2000 to boot
           * on my system as the Win2k boot loader expects the number of heads
           * to be 255, which is what the BIOS is using.
           *
           * Our algorithm for lying will be to accept the number of heads
           * reported by the kernel only if the number of cylinders reported is
           * less than 1024, but otherwise to use 255 heads.
           */
          bs.secs_track = CT_LE_W (geometry.sectors);
          if (geometry.cylinders < 1024)
            bs.heads = CT_LE_W (geometry.heads);
          else
            bs.heads = CT_LE_W (255);
          bs.hidden = CT_LE_L (geometry.start);
        }
    def_hd_params:
      /* non-partitioned floppy-like HD devices (e.g., LS120/Zip) have zero hidden sectors */
      /* we force that here to catch those cases where the kernel geometry call was not be used. */
      if (is_full_disk)
        bs.hidden = CT_LE_L (0);
      bs.media = (char) 0xf8;   /* Set up the media descriptor for a hard drive */
      bs.dir_entries[0] = (char) 0;     /* Default to 512 entries */
      bs.dir_entries[1] = (char) 2;
      if (!size_fat && blocks * (BLOCK_SIZE / hw_sector_size) > 1064960)
        {
          if (verbose)
           fprintf (stderr, "Auto-selecting FAT32 for large filesystem.\n");
          size_fat = 32;
        }
      if (size_fat == 32)
        {
          /* For FAT32, try to do the same as M$'s format command:
           * fs size < 256M: 0.5k clusters
           * fs size <   8G: 4k clusters
           * fs size <  16G: 8k clusters
           * fs size >= 16G: 16k clusters
           */
          unsigned long sz_mb = (blocks + (1 << (20 - BLOCK_SIZE_BITS)) - 1) >> (20 - BLOCK_SIZE_BITS);
          bs.cluster_size = sz_mb >= 16 * 1024 ? 32 : sz_mb >= 8 * 1024 ? 16 : sz_mb >= 256 ? 8 : 1;
        }
      else
        {
          /* FAT12 and FAT16: start at 4 sectors per cluster */
          bs.cluster_size = (char) 4;
        }
    } /* else is a hard drive */

}


/* Create the filesystem data tables */
static void
setup_tables (void)
{
  unsigned num_sectors;
  unsigned cluster_count = 0, fat_length;
  unsigned fatdata;             /* Sectors for FATs + data area */
  unsigned tmp_uvalue;

  struct tm *ctime;
  struct msdos_volume_info *vi = (size_fat == 32 ? &bs.fat32.vi : &bs.oldfat.vi);

  if (atari_format)
    /* On Atari, the first few bytes of the boot sector are assigned
     * differently: The jump code is only 2 bytes (and m68k machine code
     * :-), then 6 bytes filler (ignored), then 3 byte serial number. */
    memcpy (bs.system_id - 1, "mkdosf", 6);
  else
    strcpy (bs.system_id, "mkdosfs");
  if (sectors_per_cluster)
    bs.cluster_size = (char) sectors_per_cluster;
  if (size_fat == 32)
    {
      /* Under FAT32, the root dir is in a cluster chain, and this is
       * signaled by bs.dir_entries being 0. */
      bs.dir_entries[0] = bs.dir_entries[1] = (char) 0;
      root_dir_entries = 0;
    }
  else if (root_dir_entries)
    {
      /* Override default from establish_params() */
      bs.dir_entries[0] = (char) (root_dir_entries & 0x00ff);
      bs.dir_entries[1] = (char) ((root_dir_entries & 0xff00) >> 8);
    }
  else
    root_dir_entries = bs.dir_entries[0] + (bs.dir_entries[1] << 8);

  if (atari_format)
    {
      bs.system_id[5] = (unsigned char) (volume_id & 0x000000ff);
      bs.system_id[6] = (unsigned char) ((volume_id & 0x0000ff00) >> 8);
      bs.system_id[7] = (unsigned char) ((volume_id & 0x00ff0000) >> 16);
    }
  else
    {
      vi->volume_id[0] = (unsigned char) (volume_id & 0x000000ff);
      vi->volume_id[1] = (unsigned char) ((volume_id & 0x0000ff00) >> 8);
      vi->volume_id[2] = (unsigned char) ((volume_id & 0x00ff0000) >> 16);
      vi->volume_id[3] = (unsigned char) (volume_id >> 24);
    }

  /* we use the default bs.media to signal if we have a HD or not */
  /* we check this now before using any user given media descriptor */
  if (bs.media == 0xf8)
    {
      vi->drive_number = HD_DRIVE_NUMBER; /* Set bios drive number to 80h */
    }
  else
    {
      vi->drive_number = FD_DRIVE_NUMBER; /* Set bios drive number to 00h */
    }
  
  /* if user specified a BIOS drive number, use it */
  if (use_bios_drive_number)
    {
      vi->drive_number = (__u8) bios_drive_number;
    }

 /* if user specified a media descriptor, use it */
  if (use_media_descriptor)
    {
      bs.media = (__u8) media_descriptor;
    }

  if (!atari_format)
    {
      memcpy (vi->volume_label, volume_name, 11);

      memcpy (bs.boot_jump, dummy_boot_jump, 3);
      /* Patch in the correct offset to the boot code */
      bs.boot_jump[1] = ((size_fat == 32 ? (char *) &bs.fat32.boot_code : (char *) &bs.oldfat.boot_code) - (char *) &bs) - 2;

      if (size_fat == 32)
        {
          int offset = (char *) &bs.fat32.boot_code - (char *) &bs + MESSAGE_OFFSET + 0x7c00;
          if (dummy_boot_code[BOOTCODE_FAT32_SIZE - 1])
            fprintf (stderr, "Warning: message too long; truncated.\n");
          dummy_boot_code[BOOTCODE_FAT32_SIZE - 1] = 0;
          memcpy (bs.fat32.boot_code, dummy_boot_code, BOOTCODE_FAT32_SIZE);
          bs.fat32.boot_code[MSG_OFFSET_OFFSET] = offset & 0xff;
          bs.fat32.boot_code[MSG_OFFSET_OFFSET + 1] = offset >> 8;
        }
      else
        {
          memcpy (bs.oldfat.boot_code, dummy_boot_code, BOOTCODE_SIZE);
        }
      bs.boot_sign = CT_LE_W (BOOT_SIGN);
    }
  else
    {
      memcpy (bs.boot_jump, dummy_boot_jump_m68k, 2);
    }
  if (verbose >= 2)
    printf ("Boot jump code is %02x %02x.\n", bs.boot_jump[0], bs.boot_jump[1]);

  if (!reserved_sectors)
    reserved_sectors = (size_fat == 32) ? 32 : 1;
  else
    {
      if (size_fat == 32 && reserved_sectors < 2)
        die ("On FAT32 at least 2 reserved sectors are needed.");
    }
  bs.reserved = CT_LE_W (reserved_sectors);
  if (verbose >= 2)
    printf ("Using %d reserved sectors.\n", reserved_sectors);
  bs.fats = (char) nr_fats;

  /* At this point, the "hidden sector" number, bs.hidden, should be setup
   * correctly for the given type of device/media. Now adjust it as required
   * based on other options.
   * 
   * If the number of hidden sectors is incorrect within a bootable
   * device/partition, the second stage boot loader will fail to load.
   * For (partitionless) floppies and (partitionless) superfloppy LS120/ZIP devices:
   * hidden sectors = 0.
   * For hard drive partitions:
   * hidden sectors = (BIOS geometry) start sector of partition.
   * Thanks to Petr Soucek for his September, 2002 post in the XOSL mailing
   * list about the correct value of hidden sectors.
   */
  /* Historically, mkdosfs always used zero hidden sectors for Atari format.
     This may not have been correct. Enable this code to restore a default
     of zero hidden sectors for Atari format. */
  /* if (atari_format)
     bs.hidden = CT_LE_L(0);
   */
  /* Allow user to have final say with respect to number of hidden sectors. */
  if (use_hidden_sectors)
    bs.hidden = CT_LE_L (hidden_sectors);
  /* In the Atari FAT12/16 format, hidden sectors is a 16 bit field. So,
     we have to check limits. There is no need to convert the value as FAT
     is a little endian system and stores the lower two bytes of 16 and 32
     bit integers the same way in addition to the fact that hidden sectors
     is the last field as there is no total_sect or other fields after it.
     We allow for a FAT32 Atari format which, presumably, uses a full 32 bit
     field here.
  */
  if (atari_format && size_fat <= 32)
    {
      tmp_uvalue = CF_LE_L (bs.hidden);
      if (tmp_uvalue & ~0xffff)
        die ("Number of hidden sectors doesn't fit in 16bit field of Atari format.\n");
    }
  /* Allow user to have final say with respect to number of heads. */
  if (use_number_of_heads)
    bs.heads = CT_LE_W (number_of_heads);

  /* Allow user to have final say with respect to number of sectors per track. */
  if (use_sectors_per_track)
    bs.secs_track = CT_LE_W (sectors_per_track);

  num_sectors = (long long) blocks *BLOCK_SIZE / sector_size;
  if (!atari_format)
    {
      unsigned fatlength12, fatlength16, fatlength32;
      unsigned maxclust12, maxclust16, maxclust32;
      unsigned clust12, clust16, clust32;
      int maxclustsize;

      fatdata = num_sectors - cdiv (root_dir_entries * 32, sector_size) - reserved_sectors;

      if (sectors_per_cluster)
        bs.cluster_size = maxclustsize = sectors_per_cluster;
      else
        /* An initial guess for bs.cluster_size should already be set */
        maxclustsize = 128;

      if (verbose >= 2)
        printf ("%d sectors for FAT+data, starting with %d sectors/cluster.\n", fatdata, bs.cluster_size);
      do
        {
          if (verbose >= 2)
            printf ("Trying with %d sectors/cluster:\n", bs.cluster_size);

          /* The factor 2 below avoids cut-off errors for nr_fats == 1.
           * The "nr_fats*3" is for the reserved first two FAT entries */
          clust12 = 2 * ((long long) fatdata * sector_size + nr_fats * 3) /
            (2 * (int) bs.cluster_size * sector_size + nr_fats * 3);
          fatlength12 = cdiv (((clust12 + 2) * 3 + 1) >> 1, sector_size);
          /* Need to recalculate number of clusters, since the unused parts of the
           * FATS and data area together could make up space for an additional,
           * not really present cluster. */
          clust12 = (fatdata - nr_fats * fatlength12) / bs.cluster_size;
          maxclust12 = (fatlength12 * 2 * sector_size) / 3;
          if (maxclust12 > MAX_CLUST_12)
            maxclust12 = MAX_CLUST_12;
          if (verbose >= 2)
            printf ("FAT12: #clu=%u, fatlen=%u, maxclu=%u, limit=%u\n", clust12, fatlength12, maxclust12, MAX_CLUST_12);
          if (clust12 > maxclust12 - 2)
            {
              clust12 = 0;
              if (verbose >= 2)
                printf ("FAT12: too many clusters.\n");
            }

          clust16 = ((long long) fatdata * sector_size + nr_fats * 4) / ((int) bs.cluster_size * sector_size + nr_fats * 2);
          fatlength16 = cdiv ((clust16 + 2) * 2, sector_size);
          /* Need to recalculate number of clusters, since the unused parts of the
           * FATS and data area together could make up space for an additional,
           * not really present cluster. */
          clust16 = (fatdata - nr_fats * fatlength16) / bs.cluster_size;
          maxclust16 = (fatlength16 * sector_size) / 2;
          if (maxclust16 > MAX_CLUST_16)
            maxclust16 = MAX_CLUST_16;
          if (verbose >= 2)
            printf ("FAT16: #clu=%u, fatlen=%u, maxclu=%u, limit=%u\n", clust16, fatlength16, maxclust16, MAX_CLUST_16);
          if (clust16 > maxclust16 - 2)
            {
              if (verbose >= 2)
                fprintf (stderr, "FAT16: too many clusters.\n");
              clust16 = 0;
            }
          /* The < 4078 avoids that the filesystem will be misdetected as having a
           * 12 bit FAT. */
          if (clust16 < FAT12_THRESHOLD && !(size_fat_by_user && size_fat == 16))
            {
              if (verbose >= 2)
                fprintf (stderr, clust16 < FAT12_THRESHOLD ? "FAT16: would be misdetected as FAT12.\n" : "FAT16: too many clusters.\n");
              clust16 = 0;
            }

          clust32 = ((long long) fatdata * sector_size + nr_fats * 8) / ((int) bs.cluster_size * sector_size + nr_fats * 4);
          fatlength32 = cdiv ((clust32 + 2) * 4, sector_size);
          /* Need to recalculate number of clusters, since the unused parts of the
           * FATS and data area together could make up space for an additional,
           * not really present cluster. */
          clust32 = (fatdata - nr_fats * fatlength32) / bs.cluster_size;
          maxclust32 = (fatlength32 * sector_size) / 4;
          if (maxclust32 > MAX_CLUST_32)
            maxclust32 = MAX_CLUST_32;
          if (clust32 && clust32 < MIN_CLUST_32 && !(size_fat_by_user && size_fat == 32))
            {
              clust32 = 0;
              if (verbose >= 2)
                fprintf (stderr, "FAT32: not enough clusters (%d).\n", MIN_CLUST_32);
            }
          if (verbose >= 2)
            printf ("FAT32: #clu=%u, fatlen=%u, maxclu=%u, limit=%u\n", clust32, fatlength32, maxclust32, MAX_CLUST_32);
          if (clust32 > maxclust32)
            {
              clust32 = 0;
              if (verbose >= 2)
                fprintf (stderr, "FAT32: too many clusters.\n");
            }

          if ((clust12 && (size_fat == 0 || size_fat == 12)) ||
              (clust16 && (size_fat == 0 || size_fat == 16)) || (clust32 && size_fat == 32))
            break;

          bs.cluster_size <<= 1;
        }
      while (bs.cluster_size && bs.cluster_size <= maxclustsize);

      /* Use the optimal FAT12/16 size if not specified by now. */
      if (!size_fat)
        {
          size_fat = (clust16 > clust12) ? 16 : 12;
          if (verbose >= 2)
            printf ("Choosing %d bits for FAT.\n", size_fat);
        }

      switch (size_fat)
        {
        case 12:
          cluster_count = clust12;
          fat_length = fatlength12;
          bs.fat_length = CT_LE_W (fatlength12);
          memcpy (vi->fs_type, MSDOS_FAT12_SIGN, 8);
          break;

        case 16:
          if (clust16 < FAT12_THRESHOLD)
            {
              if (size_fat_by_user)
                {
                  fprintf (stderr, "WARNING: Not enough clusters for a "
                           "16 bit FAT! The filesystem will be\n"
                           "misinterpreted as having a 12 bit FAT without " "mount option \"fat=16\".\n");
                }
              else
                {
                  fprintf (stderr, "This filesystem has an unfortunate size. "
                           "A 12 bit FAT cannot provide\n"
                           "enough clusters, but a 16 bit FAT takes up a little "
                           "bit more space so that\n"
                           "the total number of clusters becomes less than the "
                           "threshold value for\n" "distinction between 12 and 16 bit FATs.\n");
                  die ("Make the file system a bit smaller manually.");
                }
            }
          cluster_count = clust16;
          fat_length = fatlength16;
          bs.fat_length = CT_LE_W (fatlength16);
          memcpy (vi->fs_type, MSDOS_FAT16_SIGN, 8);
          break;

        case 32:
          cluster_count = clust32;
          fat_length = fatlength32;
          bs.fat_length = CT_LE_W (0);
          bs.fat32.fat32_length = CT_LE_L (fatlength32);
          memcpy (vi->fs_type, MSDOS_FAT32_SIGN, 8);
          break;

        default:
          die ("FAT not 12, 16 or 32 bits.");
        }
    }
  else
    {                           /* atari_format */
      unsigned clusters, maxclust;

      /* GEMDOS always uses a 12 bit FAT on floppies, and always a 16 bit FAT on
       * hard disks. So use 12 bit if the size of the file system suggests that
       * this fs is for a floppy disk, if the user hasn't explicitly requested a
       * size.
       */
      if (!size_fat)
        size_fat = (num_sectors == 1440 || num_sectors == 2400 || num_sectors == 2880 || num_sectors == 5760) ? 12 : 16;
      if (verbose >= 2)
        printf ("Choosing %d bits for FAT.\n", size_fat);

      /* Atari format: cluster size should be 2, except explicitly requested by
       * the user, since GEMDOS doesn't like other cluster sizes very much.
       * Instead, tune the sector size for the FS to fit.
       */
      bs.cluster_size = sectors_per_cluster ? sectors_per_cluster : 2;
      if (!sector_size_set)
        {
          while (num_sectors > GEMDOS_MAX_SECTORS)
            {
              num_sectors >>= 1;
              sector_size <<= 1;
            }
        }
      if (verbose >= 2)
        printf ("Sector size must be %d to have less than %d logical sectors.\n", sector_size, GEMDOS_MAX_SECTORS);

      /* Check if there are enough FAT indices for how much clusters we have */
      do
        {
          fatdata = num_sectors - cdiv (root_dir_entries * 32, sector_size) - reserved_sectors;
          /* The factor 2 below avoids cut-off errors for nr_fats == 1 and
           * size_fat == 12
           * The "2*nr_fats*size_fat/8" is for the reserved first two FAT entries
           */
          clusters =
            (2 *
             ((long long) fatdata * sector_size -
              2 * nr_fats * size_fat / 8)) / (2 * ((int) bs.cluster_size * sector_size + nr_fats * size_fat / 8));
          fat_length = cdiv ((clusters + 2) * size_fat / 8, sector_size);
          /* Need to recalculate number of clusters, since the unused parts of the
           * FATS and data area together could make up space for an additional,
           * not really present cluster. */
          clusters = (fatdata - nr_fats * fat_length) / bs.cluster_size;
          maxclust = (fat_length * sector_size * 8) / size_fat;
          if (verbose >= 2)
            printf ("ss=%d: #clu=%d, fat_len=%d, maxclu=%d\n", sector_size, clusters, fat_length, maxclust);

          /* last 10 cluster numbers are special (except FAT32: 4 high bits rsvd);
           * first two numbers are reserved */
          if (maxclust <= (size_fat == 32 ? MAX_CLUST_32 : (1 << size_fat) - 0x10) && clusters <= maxclust - 2)
            break;
          if (verbose >= 2)
            fprintf (stderr, clusters > maxclust - 2 ? "Too many clusters.\n" : "FAT too big.\n");

          /* need to increment sector_size once more to  */
          if (sector_size_set)
            die ("With this sector size, the maximum number of FAT entries " "would be exceeded.");
          num_sectors >>= 1;
          sector_size <<= 1;
        }
      while (sector_size <= GEMDOS_MAX_SECTOR_SIZE);

      if (sector_size > GEMDOS_MAX_SECTOR_SIZE)
        die ("Would need a sector size > 16k, which GEMDOS can't work with.");

      cluster_count = clusters;
      if (size_fat != 32)
        bs.fat_length = CT_LE_W (fat_length);
      else
        {
          bs.fat_length = 0;
          bs.fat32.fat32_length = CT_LE_L (fat_length);
        }
    }

  bs.sector_size[0] = (char) (sector_size & 0x00ff);
  bs.sector_size[1] = (char) ((sector_size & 0xff00) >> 8);

  if (size_fat == 32)
    {
      /* set up additional FAT32 fields */
      bs.fat32.flags = CT_LE_W (0);
      bs.fat32.version[0] = 0;
      bs.fat32.version[1] = 0;
      bs.fat32.root_cluster = CT_LE_L (2);
      bs.fat32.info_sector = CT_LE_W (FSINFO_SECTOR);

      /* autoset backup boot sector location if not specified */
      /* no backup boot sector when have less than five reserved sectors because */
      /* we need one for the boot sector, one for the FSInfo sector, one for the */
      /* second part of the boot loader, and two for the backup copies of the */
      /* boot and FSInfo sectors */
      if (!backup_boot)
        backup_boot = (reserved_sectors >= 8) ? 6 : (reserved_sectors >= 5) ? reserved_sectors - 2 : 0;

      /* don't allow the backup boot sector to be on top of the FSInfo sector */
      /* or sector 2 which may be a second stage boot loader */
      /* the argument range check should never allow values < 3 anyway. */
      if (backup_boot == 1)
        die ("Backup boot sector cannot be sector 1.");
      else if (backup_boot == 2)
        die ("Backup boot sector cannot be sector 2.");
      /* also, verify backup FSInfo sector is within the valid range */
      /* note that zero for the backup boot sector location is always */
      /* OK as it means no backup sectors */
      if (backup_boot && (backup_boot + 1) >= reserved_sectors)
        die ("Backup boot/FSInfo sector is beyond the range of reserved sectors.");

      bs.fat32.backup_boot = CT_LE_W (backup_boot);
      memset (&bs.fat32.reserved2, 0, sizeof (bs.fat32.reserved2));
    }

  if (atari_format)
    {
      /* Just some consistency checks */
      if (num_sectors >= GEMDOS_MAX_SECTORS)
        die ("GEMDOS can't handle more than 65531 sectors.");
      else if (num_sectors >= OLDGEMDOS_MAX_SECTORS)
        fprintf (stderr, "Warning: More than 32765 sector need TOS 1.04 or higher.\n");
    }
  if (num_sectors >= 65536)
    {
      bs.sectors[0] = (char) 0;
      bs.sectors[1] = (char) 0;
      bs.total_sect = CT_LE_L (num_sectors);
    }
  else
    {
      bs.sectors[0] = (char) (num_sectors & 0x00ff);
      bs.sectors[1] = (char) ((num_sectors & 0xff00) >> 8);
      if (!atari_format)
        bs.total_sect = CT_LE_L (0);
    }

  if (!atari_format)
    vi->ext_boot_sign = MSDOS_EXT_SIGN;

  if (!cluster_count)
    {
      if (sectors_per_cluster)  /* If yes, die if we'd spec'd sectors per cluster */
        die ("Too many clusters for file system - try more sectors per cluster.");
      else
        die ("Attempting to create a too large file system.");
    }


  /* The two following variables are in hardware sectors */
  start_data_hw_sector = (reserved_sectors + nr_fats * fat_length) * (sector_size / hw_sector_size);
  start_data_block = (start_data_hw_sector + (BLOCK_SIZE / hw_sector_size) - 1) / (BLOCK_SIZE / hw_sector_size);

  if (blocks < start_data_block + 32)   /* Arbitrary undersize file system! */
    die ("Too few blocks for viable file system.");

  /* parameter summary */
  if (verbose)
    {
      printf
        ("BIOS geometry used for %s: %d head%s and %d sector%s per track.\n",
         device_name, CF_LE_W (bs.heads),
         (CF_LE_W (bs.heads) != 1) ? "s" : "", CF_LE_W (bs.secs_track), (CF_LE_W (bs.secs_track) != 1) ? "s" : "");
      printf ("Using 0x%02x for the BIOS physical drive number.\n", (int) (vi->drive_number));
      printf ("Using %u for the start sector number (hidden sectors).\n", CF_LE_L (bs.hidden));
      printf ("Logical sector size is %d. Hardware sector size is %d.\n", sector_size, hw_sector_size);
      printf ("Operating system block size is %d.\n", (int) BLOCK_SIZE);
      printf ("Using 0x%02x media descriptor, with %u sectors.\n", (int) (bs.media), num_sectors);
      if (size_fat == 32)
        {
          if (backup_boot)
            printf ("Using sector %d as backup boot sector.\n", backup_boot);
          else
            printf ("No backup boot sector.\n");
        }
      else
        printf ("No backup boot sector.\n");
      printf ("Filesystem has %d %d-bit FAT%s and %d sector%s per cluster.\n",
              (int) (bs.fats), size_fat, (bs.fats != 1) ? "s" : "", (int) (bs.cluster_size), (bs.cluster_size != 1) ? "s" : "");
      printf ("FAT size is %d sector%s, and provides %d cluster%s.\n",
              fat_length, (fat_length != 1) ? "s" : "", cluster_count, (cluster_count != 1) ? "s" : "");
      if (size_fat != 32)
        printf ("Root directory contains %d slots.\n", (int) (bs.dir_entries[0]) + (int) (bs.dir_entries[1]) * 256);
      printf ("Volume ID is %08lx, ", volume_id & (atari_format ? 0x00ffffff : 0xffffffff));
      if (strcmp (volume_name, "           "))
        printf ("volume label is `%s'.\n", volume_name);
      else
        printf ("no volume label.\n");
      if (use_template)
        printf ("Boot code template file length: %d bytes, %d sectors.\n", template_size, template_sectors);
      else
        printf ("No boot code template file used.\n");
    }

  /* Make the file allocation tables! */

  if ((fat = (unsigned char *) malloc (fat_length * sector_size)) == NULL)
    die ("Unable to allocate space for FAT image in memory.");

  memset (fat, 0, fat_length * sector_size);

  mark_FAT_cluster (0, 0xffffffff);     /* Initial fat entries */
  mark_FAT_cluster (1, 0xffffffff);
  fat[0] = (unsigned char) bs.media;    /* Put media type in first byte! */
  if (size_fat == 32)
    {
      /* Mark cluster 2 as EOF (used for root dir) */
      mark_FAT_cluster (2, FAT_EOF);
    }

  /* Make the root directory entries */

  size_root_dir = (size_fat == 32) ?
    bs.cluster_size * sector_size : (((int) bs.dir_entries[1] * 256 + (int) bs.dir_entries[0]) * sizeof (struct msdos_dir_entry));
  if ((root_dir = (struct msdos_dir_entry *) malloc (size_root_dir)) == NULL)
    {
      free (fat); /* Tidy up before we die! */
      die ("Unable to allocate space for root directory in memory.");
    }

  memset (root_dir, 0, size_root_dir);
  if (memcmp (volume_name, "           ", 11))
    {
      struct msdos_dir_entry *de = &root_dir[0];
      memcpy (de->name, volume_name, 11);
      de->attr = ATTR_VOLUME;
      ctime = localtime (&create_time);
      de->time = CT_LE_W ((unsigned short) ((ctime->tm_sec >> 1) + (ctime->tm_min << 5) + (ctime->tm_hour << 11)));
      de->date = CT_LE_W ((unsigned short) (ctime->tm_mday + ((ctime->tm_mon + 1) << 5) + ((ctime->tm_year - 80) << 9)));
      de->ctime_ms = 0;
      de->ctime = de->time;
      de->cdate = de->date;
      de->adate = de->date;
      de->starthi = CT_LE_W (0);
      de->start = CT_LE_W (0);
      de->size = CT_LE_L (0);
    }

  if (size_fat == 32)
    {
      /* For FAT32, create an info sector */
      struct fat32_fsinfo *info;

      if (!(info_sector = malloc (sector_size)))
        die ("Out of memory.");
      memset (info_sector, 0, sector_size);
      /* fsinfo structure is at offset 0x1e0 in info sector by observation */
      info = (struct fat32_fsinfo *) (info_sector + 0x1e0);

      /* Info sector magic */
      info_sector[0] = 'R';
      info_sector[1] = 'R';
      info_sector[2] = 'a';
      info_sector[3] = 'A';

      /* Magic for fsinfo structure */
      info->signature = CT_LE_L (0x61417272);
      /* We've allocated cluster 2 for the root dir. */
      info->free_clusters = CT_LE_L (cluster_count - 1);
      info->next_cluster = CT_LE_L (2);

      /* Info sector also must have boot sign */
      *(__u16 *) (info_sector + 0x1fe) = CT_LE_W (BOOT_SIGN);
    }

  /* create a blank sector */
  if (!(blank_sector = malloc (sector_size)))
    die ("Out of memory.");
  memset (blank_sector, 0, sector_size);
}


/* Write the new filesystem's data tables to wherever they're going to end up! */
#define error(str)                              \
  do {                                          \
    free (fat);                                 \
    if (info_sector) free (info_sector);        \
    free (root_dir);                            \
    die (str);                                  \
  } while(0)

#define seekto(pos,errstr)                                              \
  do {                                                                  \
    loff_t __pos = (pos);                                               \
    if (lseek (dev, __pos, SEEK_SET) != __pos) {                        \
        perror ("lseek");                                               \
        error ("seek to " errstr " failed whilst writing tables");      \
    }                                                                   \
  } while(0)

#define writebuf(buf,size,errstr)                       \
  do {                                                  \
    int __size = (size);                                \
    if (write (dev, buf, __size) != __size) {           \
        perror ("write");                               \
        error ("failed whilst writing " errstr);        \
    }                                                   \
  } while(0)


static void
write_tables (void)
{
  int x;
  int fat_length;

  fat_length = (size_fat == 32) ? CF_LE_L (bs.fat32.fat32_length) : CF_LE_W (bs.fat_length);

  seekto (0, "start of device");
  /* clear all reserved sectors */
  for (x = 0; x < reserved_sectors; ++x)
    writebuf (blank_sector, sector_size, "reserved sector");
  /* seek back to sector 0 and write the boot sector */
  seekto (0, "boot sector");
  writebuf ((char *) &bs, sizeof (struct msdos_boot_sector), "boot sector");
  /* on FAT32, write the FSInfo sector and backup boot/FSInfo sectors */
  if (size_fat == 32)
    {
      seekto (FSINFO_SECTOR * sector_size, "FSInfo sector");
      writebuf (info_sector, 512, "FSInfo sector");
      if (backup_boot != 0)
        {
          seekto (backup_boot * sector_size, "backup boot sector");
          writebuf ((char *) &bs, sizeof (struct msdos_boot_sector), "backup boot sector");
          /* write out a backup FSInfo sector too, we have ensured we have the room */
          seekto ((backup_boot + 1) * sector_size, "backup FSInfo sector");
          writebuf (info_sector, 512, "FSInfo sector");
        }
    }
  /* seek to start of FATS and write them all */
  seekto (reserved_sectors * sector_size, "first FAT");
  for (x = 1; x <= nr_fats; x++)
    writebuf (fat, fat_length * sector_size, "FAT");
  /* Write the root directory directly after the last FAT. This is the root
   * dir area on FAT12/16, and the first cluster on FAT32. */
  writebuf ((char *) root_dir, size_root_dir, "root directory");

  if (use_template == 1)
    {
      /* copy template areas into reserved sectors */
      seekto (0, "Start of partition");
      if (size_fat == 32)
        { /* FAT32 */
          writebuf (template_boot_code, 3, "jump instruction");
          seekto (0x5a, "sector 0 boot code area");
          writebuf (template_boot_code + 0x5a, 420, "sector 0 boot code area");
          /* It is legal to have data after the "end of sector marker" 0xAA55 at 0x01FE */
          /* If the sectors extend beyond this marker, copy that data too */
          if (lesser_sector_size > 0x200)
            {
              seekto (0x200, "sector 0 after end marker");
              writebuf (template_boot_code + 0x200, lesser_sector_size - 0x200, "sector 0 after end marker");
            }
          /* do the same for the backup boot area if used */
          if (backup_boot != 0)
            {
              seekto (backup_boot * sector_size, "backup boot sector");
              writebuf (template_boot_code, 3, "backup jump instruction");
              seekto (backup_boot * sector_size + 0x5a, "backup boot sector boot code area");
              writebuf (template_boot_code + 0x5a, 420, "backup boot sector boot code area");
              /* It is legal to have data after the "end of sector marker" 0xAA55 at 0x01FE */
              /* If the sectors extend into this region, copy that data too */
              if (lesser_sector_size > 0x200)
                {
                  seekto (backup_boot * sector_size + 0x200, "backup boot sector after end marker");
                  writebuf (template_boot_code + 0x200, lesser_sector_size - 0x200, "backup boot sector after end marker");
                }
            }
          for (current_sector = 2; current_sector < template_sectors_can_copy; current_sector++)
            {
              /* skip all backup and fsinfo sectors */
              if (current_sector == backup_boot
                  || current_sector == FSINFO_SECTOR
                  || current_sector == backup_boot + 1
                  || current_sector == template_backup_sector
                  || current_sector == template_fsinfo_sector
                  || current_sector == template_backup_sector + 1)
                continue;
              seekto (current_sector * sector_size, "reserved sector");
              writebuf (template_boot_code + (current_sector * sector_size), lesser_sector_size, "reserved sector");
            } /* for all sectors after 1 */
        }
      else
        { /* FAT12/16 */
          writebuf (template_boot_code, 3, "jump instruction");
          seekto (0x3e, "sector 0 boot code area");
          writebuf (template_boot_code + 0x3e, 448, "sector 0 boot code area");
          /* It is legal to have data after the "end of sector marker" 0xAA55 at 0x01FE */
          /* If the sectors extend into this region, copy that data too */
          if (lesser_sector_size > 0x200)
            {
              seekto (0x200, "sector 0 after end marker");
              writebuf (template_boot_code + 0x200, lesser_sector_size - 0x200, "sector 0 after end marker");
            }
        }
    }

  if (blank_sector)
    free (blank_sector);
  if (info_sector)
    free (info_sector);
  free (root_dir);              /* Free up the root directory space from setup_tables */
  free (fat);                   /* Free up the fat table space reserved during setup_tables */
}


/* Report the command usage and return a failure error code */
void
usage (void)
{
  fatal_error ("\
Usage: mkdosfs [-A] [-b backup-boot-sector] [-B bootcode-file] [-c] [-C]\n\
       [-d BIOS-drive-number] [-f number-of-FATs] [-F fat-size]\n\
       [-h start-sector] [-H heads] [-i volume-id] [-I] [-l bad-block-file]\n\
       [-m message-file] [-M media-descriptor] [-n volume-name]\n\
       [-r root-dir-entries] [-R reserved-sectors] [-s sectors-per-cluster]\n\
       [-S logical-sector-size] [-t sectors-per-track]\n\
       [-T hardware-sector-size] [-v] device [block-count]\n");
}

/*
 * ++roman: On m68k, check if this is an Atari; if yes, turn on Atari variant
 * of MS-DOS filesystem by default.
 */
static void
check_atari (void)
{
#ifdef __mc68000__
  FILE *f;
  char line[128], *p;

  if (!(f = fopen ("/proc/hardware", "r")))
    {
      perror ("/proc/hardware");
      return;
    }

  while (fgets (line, sizeof (line), f))
    {
      if (strncmp (line, "Model:", 6) == 0)
        {
          p = line + 6;
          p += strspn (p, " \t");
          if (strncmp (p, "Atari ", 6) == 0)
            atari_format = 1;
          break;
        }
    }
  fclose (f);
#endif
}

/* The "main" entry point into the utility - we pick up the options
   and attempt to process them in some sort of sensible way.
   In the event that some/all of the options are invalid we need to
   tell the user so that something can be done! */
int
main (int argc, char **argv)
{
  int c;
  char *tmp;
  char *listfile = NULL;
  FILE *msgfile;
  int fdbootfile;
  int numread;
  struct stat statbuf;
  int i = 0, pos, ch;
  int create = 0;
  unsigned long long cblocks = 0;

  if (argc && *argv)
    {                           /* What's the program name? */
      char *p;
      program_name = *argv;
      if ((p = strrchr (program_name, '/')))
        program_name = p + 1;
    }

  time (&create_time);
  volume_id = (long) create_time;       /* Default volume ID = creation time */
  check_atari ();

  printf ("%s " VERSION " (" VERSION_DATE ")\n", program_name);

  while ((c = getopt (argc, argv, "AB:b:cCd:f:F:h:H:Ii:l:m:M:n:r:R:s:S:t:T:v")) != EOF)
    /* Scan the command line for options */
    switch (c)
      {
      case 'A':                /* A: toggle Atari format */
        atari_format = !atari_format;
        break;

      case 'b':                /* b : location of backup boot sector */
        acquired_option_val = strtol (optarg, &tmp, 0);
        if (*tmp || acquired_option_val < 3 || acquired_option_val > 0xffff)
          {
            fprintf (stderr, "Bad value for backup boot sector: %s.\n", optarg);
            usage ();
          }
        backup_boot = (int) acquired_option_val;
        break;

      case 'B':                /* B : read in bootcode */
        if (strcmp (optarg, "-"))
          {
            fdbootfile = open (optarg, O_RDONLY);
            if (fdbootfile < 0)
              {
                perror ("open");
                fprintf (stderr, "Unable to open boot code template file `%s'.\n", optarg);
                exit (1);
              }
          }
        else
          {
            fdbootfile = STDIN_FILENO;
            if (fdbootfile < 0)
              {
                fprintf (stderr, "Unable to read boot code template from standard input.\n");
                exit (1);
              }
          }

        /* allocate memory for template, use an additional byte for overlength file detection */
        if (!(template_boot_code = malloc (BOOT_TEMPLATE_SIZE + 1)))
          die ("Out of memory while allocating for boot code template.");

        use_template = 1;
        template_size = 0;

        do
          {
            numread =
              (int) read (fdbootfile, &template_boot_code[template_size], BOOT_TEMPLATE_SIZE + 1 - (size_t) template_size);

            if (numread > 0)
              template_size += numread;

          }
        while (((numread < 0 && errno == EINTR) || numread > 0) && (template_size < BOOT_TEMPLATE_SIZE + 1));

        if (numread < 0)
          {
            perror ("read");
            die ("Error while reading boot code template file.\n");
          }

        /* warn if file is longer than BOOT_TEMPLATE_SIZE */
        if (template_size > BOOT_TEMPLATE_SIZE)
          {
            fprintf (stderr, "Warning: boot code template too long; truncated after %d bytes.\n", BOOT_TEMPLATE_SIZE);
            template_size = BOOT_TEMPLATE_SIZE;
          }
        /* if template_boot_code not full, zero to end */
        else if (template_size < BOOT_TEMPLATE_SIZE)
          {
            memset (&template_boot_code[template_size], 0, BOOT_TEMPLATE_SIZE - (size_t) template_size);
          }
        template_boot_code[BOOT_TEMPLATE_SIZE] = 0;     /* optional - zero overflow byte at end */

        if (fdbootfile != STDIN_FILENO)
          close (fdbootfile);

        /* verify template is sane */
        if (((unsigned char) template_boot_code[0x01FE] != 0x55) || ((unsigned char) template_boot_code[0x01FF] != 0xAA))
          die ("Boot code template invalid - no 0xAA55 end of sector zero marker.");

        template_sector_size = (unsigned char) template_boot_code[0x0C];
        template_sector_size = template_sector_size << 8;
        template_sector_size = template_sector_size + (unsigned char) template_boot_code[0x0B];

        template_reserved_sectors = (unsigned char) template_boot_code[0x0F];
        template_reserved_sectors = template_reserved_sectors << 8;
        template_reserved_sectors = template_reserved_sectors + (unsigned char) template_boot_code[0x0E];

        if (template_sector_size != 512 && template_sector_size != 1024 &&
            template_sector_size != 2048 && template_sector_size != 4096 &&
            template_sector_size != 8192 && template_sector_size != 16384 && template_sector_size != 32768)
          die ("Boot code template invalid - bad number of bytes per sector.");

        /* get total number of template sectors, silently extend last sector if partial,
           unless doing so would cause BOOT_TEMPLATE_SIZE to be exceeded */
        template_sectors = template_size / template_sector_size;
        if (template_size != template_sectors * template_sector_size)
          {
            template_sectors = template_sectors + 1;
            if (template_sectors * template_sector_size > BOOT_TEMPLATE_SIZE)
              {
                fprintf (stderr,
                  "Warning: End of last sector of boot code template extends beyond %d bytes. Ignoring partial sector.\n",
                  BOOT_TEMPLATE_SIZE);
                template_sectors = template_sectors - 1;
              }
          }

        if (template_sectors < 1)
          die ("Boot code template invalid - does not have at least one full sector.");

        if ((unsigned char) template_boot_code[0x10] == 0)
          die ("Boot code template invalid - zero number of FATs.");

        if ((unsigned char) template_boot_code[0x16] != 0)
          template_fat_type = 16;       /* FAT12/16 */
        else
          {
            if (((unsigned char) template_boot_code[0x11] != 0) ||
                ((unsigned char) template_boot_code[0x12] != 0) ||
                ((unsigned char) template_boot_code[0x13] != 0) || ((unsigned char) template_boot_code[0x14] != 0))
              die ("Boot code template invalid - FAT32-like, but nonzero 0x11-0x14.");
            else
              {
                template_fat_type = 32; /* is FAT32, get fsinfo and backup locations */
                template_fsinfo_sector = (unsigned char) template_boot_code[0x31];
                template_fsinfo_sector = template_fsinfo_sector << 8;
                template_fsinfo_sector = template_fsinfo_sector + (unsigned char) template_boot_code[0x30];

                template_backup_sector = (unsigned char) template_boot_code[0x35];
                template_backup_sector = template_backup_sector << 8;
                template_backup_sector = template_backup_sector + (unsigned char) template_boot_code[0x34];
              }
          }
        break;

      case 'c':                /* c : Check FS as we build it */
        check = TRUE;
        break;

      case 'C':                /* C : Create a new file */
        create = TRUE;
        break;

      case 'd':                /* d : BIOS drive number */
        acquired_option_val = strtol (optarg, &tmp, 0);
        if (*tmp || acquired_option_val < 0x0000 || acquired_option_val > 0x00ff)
          {
            fprintf (stderr,"BIOS physical drive number out of range: %s.\n", optarg);
            usage ();
          }
        bios_drive_number = (int) acquired_option_val;
        use_bios_drive_number = 1;
        break;

      case 'f':                /* f : Choose number of FATs */
        acquired_option_val = strtol (optarg, &tmp, 0);
        if (*tmp || acquired_option_val < 1 || acquired_option_val > 4)
          {
            fprintf (stderr,"Bad number of FATs: %s.\n", optarg);
            usage ();
          }
        nr_fats = acquired_option_val;
        break;

      case 'F':                /* F : Choose FAT size */
        acquired_option_val = strtol (optarg, &tmp, 0);
        if (*tmp || (acquired_option_val != 12 && acquired_option_val != 16 && acquired_option_val != 32))
          {
            fprintf (stderr,"Bad FAT type: %s.\n", optarg);
            usage ();
          }
        size_fat = acquired_option_val;
        size_fat_by_user = 1;
        break;

      case 'h':                /* h : start sector (hidden sectors) */
        acquired_option_val = strtol (optarg, &tmp, 0);
        if (*tmp || acquired_option_val < 0 || acquired_option_val > 0xffffffff)
          {
            fprintf (stderr,"Bad start sector number: %s.\n", optarg);
            usage ();
          }
        hidden_sectors = (unsigned int) acquired_option_val;
        use_hidden_sectors = 1;
        break;

      case 'H':                /* H : number of heads */
        acquired_option_val = strtol (optarg, &tmp, 0);
        if (*tmp || acquired_option_val < 0x0000 || acquired_option_val > 0xffff)
          {
            fprintf (stderr,"Bad number of heads: %s.\n", optarg);
            usage ();
          }
        number_of_heads = (int) acquired_option_val;
        use_number_of_heads = 1;
        break;

      case 'I':
        ignore_full_disk = 1;
        break;

      case 'i':                /* i : specify volume ID */
        volume_id = strtoul (optarg, &tmp, 16);
        if (*tmp)
          {
            fprintf (stderr,"Volume ID must be a hexadecimal number.\n");
            usage ();
          }
        break;

      case 'l':                /* l : Bad block filename */
        listfile = optarg;
        break;

      case 'm':                /* m : Set boot message */
        if (strcmp (optarg, "-"))
          {
            msgfile = fopen (optarg, "r");
            if (!msgfile)
              perror (optarg);
          }
        else
          msgfile = stdin;

        if (msgfile)
          {
            /* The dummy boot code ends at offset 448 and needs a null terminator */
            i = MESSAGE_OFFSET;
            pos = 0;            /* We are at beginning of line */
            do
              {
                ch = getc (msgfile);
                switch (ch)
                  {
                  case '\r':   /* Ignore CRs */
                  case '\0':   /* and nulls */
                    break;

                  case '\n':   /* LF -> CR+LF if necessary */
                    if (pos)    /* If not at beginning of line */
                      {
                        dummy_boot_code[i++] = '\r';
                        pos = 0;
                      }
                    dummy_boot_code[i++] = '\n';
                    break;

                  case '\t':   /* Expand tabs */
                    do
                      {
                        dummy_boot_code[i++] = ' ';
                        pos++;
                      }
                    while (pos % 8 && i < BOOTCODE_SIZE - 1);
                    break;

                  case EOF:
                    dummy_boot_code[i++] = '\0';        /* Null terminator */
                    break;

                  default:
                    dummy_boot_code[i++] = ch;  /* Store character */
                    pos++;      /* Advance position */
                    break;
                  }
              }
            while (ch != EOF && i < BOOTCODE_SIZE - 1);

            /* Fill up with zeros */
            while (i < BOOTCODE_SIZE - 1)
              dummy_boot_code[i++] = '\0';
            dummy_boot_code[BOOTCODE_SIZE - 1] = '\0';  /* Just in case */

            if (ch != EOF)
              fprintf (stderr,"Warning: message too long; truncated.\n");

            if (msgfile != stdin)
              fclose (msgfile);
          }
        break;

      case 'M':                /* M : media descriptor */
        acquired_option_val = strtol (optarg, &tmp, 0);
        if (*tmp || acquired_option_val < 0x0000 || acquired_option_val > 0x00ff)
          {
            fprintf (stderr,"Media descriptor out of range: %s.\n", optarg);
            usage ();
          }
        media_descriptor = (int) acquired_option_val;
        use_media_descriptor = 1;
        break;

      case 'n':                /* n : Volume name */
        sprintf (volume_name, "%-11.11s", optarg);
        break;

      case 'r':                /* r : Root directory entries */
        acquired_option_val = strtol (optarg, &tmp, 0);
        if (*tmp || acquired_option_val < 16 || acquired_option_val > 32768)
          {
            fprintf (stderr,"Bad number of root directory entries: %s.\n", optarg);
            usage ();
          }
        root_dir_entries = (int) acquired_option_val;
        break;

      case 'R':                /* R : number of reserved sectors */
        acquired_option_val = strtol (optarg, &tmp, 0);
        if (*tmp || acquired_option_val < 1 || acquired_option_val > 0xFFFF)
          {
            fprintf (stderr,"Bad number of reserved sectors: %s.\n", optarg);
            usage ();
          }
        reserved_sectors = (int) acquired_option_val;
        break;

      case 's':                /* s : Sectors per cluster */
        acquired_option_val = strtol (optarg, &tmp, 0);
        if (*tmp || (acquired_option_val != 1 && acquired_option_val != 2
                     && acquired_option_val != 4 && acquired_option_val != 8
                     && acquired_option_val != 16 && acquired_option_val != 32
                     && acquired_option_val != 64 && acquired_option_val != 128))
          {
            fprintf (stderr,"Bad number of sectors per cluster: %s.\n", optarg);
            usage ();
          }
        sectors_per_cluster = (int) acquired_option_val;
        break;

      case 'S':                /* S : Logical sector size */
        acquired_option_val = strtol (optarg, &tmp, 0);
        if (*tmp
            || (acquired_option_val != 512 && acquired_option_val != 1024
                && acquired_option_val != 2048 && acquired_option_val != 4096
                && acquired_option_val != 8192 && acquired_option_val != 16384 && acquired_option_val != 32768))
          {
            fprintf (stderr,"Bad logical sector size: %s.\n", optarg);
            usage ();
          }
        sector_size = (int) acquired_option_val;
        sector_size_set = 1;
        break;

      case 't':                /* t : number of sectors per track */
        acquired_option_val = strtol (optarg, &tmp, 0);
        if (*tmp || acquired_option_val < 0x0000 || acquired_option_val > 0xffff)
          {
            fprintf (stderr,"Bad number of sectors per track: %s.\n", optarg);
            usage ();
          }
        sectors_per_track = (int) acquired_option_val;
        use_sectors_per_track = 1;
        break;

      case 'T':                /* T : Hardware sector size */
        acquired_option_val = strtol (optarg, &tmp, 0);
        if (*tmp
            || (acquired_option_val != 512 && acquired_option_val != 1024
                && acquired_option_val != 2048 && acquired_option_val != 4096
                && acquired_option_val != 8192 && acquired_option_val != 16384 && acquired_option_val != 32768))
          {
            fprintf (stderr,"Bad hardware sector size: %s.\n", optarg);
            usage ();
          }
        hw_sector_size_user = (int) acquired_option_val;
        hw_sector_size_set = 1;
        break;

      case 'v':                /* v : Verbose execution */
        ++verbose;
        break;

      default:
        fprintf (stderr,"Unknown option: `%c'\n", (char) optopt);
        usage ();
      }
  if (optind < argc)
    {
      device_name = argv[optind];       /* Determine the number of blocks in the FS */

      if (!device_name)
        {
          fprintf (stderr,"No device specified.\n");
          usage ();
        }

      if (!create)
        cblocks = count_blocks (device_name);   /*  Have a look and see! */
    }
  if (optind == argc - 2)       /*  Either check the user specified number */
    {
      blocks = strtoull (argv[optind + 1], &tmp, 0);
      if (!create && blocks != cblocks)
        {
          fprintf (stderr,"Warning: block count mismatch: ");
          fprintf (stderr,"found %llu but assuming %llu.\n", cblocks, blocks);
        }
    }
  else if (optind == argc - 1)  /*  Or use value found */
    {
      if (create)
        die ("Need intended size with -C.");
      blocks = cblocks;
      tmp = "";
    }
  else
    {
      fprintf (stderr,"No device specified!\n");
      usage ();
    }
  if (*tmp)
    {
      fprintf (stderr,"Bad block count: %s.\n", argv[optind + 1]);
      usage ();
    }

  /*
  if (check && listfile)
    die ("-c and -l are incompatible.");
  */

  if (!create)
    {
      check_mount (device_name); /* Is the device already mounted? */
      dev = open (device_name, O_EXCL | O_RDWR); /* Is it a suitable device to build the FS on? */
      if (dev < 0)
        {
          perror ("open");
          die ("Unable to open %s.");
        }
    }
  else
    {
      off_t offset = blocks * BLOCK_SIZE - 1;
      char null = 0;
      /* create the file */
      dev = open (device_name, O_EXCL | O_RDWR | O_CREAT | O_TRUNC, 0666);
      if (dev < 0)
        {
          perror ("open");
          die ("Unable to create %s.");
        }
      /* seek to the intended end-1, and write one byte. this creates a
       * sparse-as-possible file of appropriate size. */
      if (lseek (dev, offset, SEEK_SET) != offset)
        {
          perror ("lseek");
          die ("Seek failed.");
        }
      if (write (dev, &null, 1) < 0)
        {
          perror ("write");
          die ("Write failed.");
        }
      if (lseek (dev, 0, SEEK_SET) != 0)
        {
          perror ("lseek");
          die ("Seek failed.");
        }
    }

  if (fstat (dev, &statbuf) < 0)
    {
      perror ("fstat");
      die ("Unable to stat %s.");
    }
  if (!S_ISBLK (statbuf.st_mode))
    {
      statbuf.st_rdev = 0;
      check = 0;
    }
  else
    /*
     * On a magneto-optical disk one doesn't need partitions.  The filesytem
     * can go directly to the whole disk.  Under other OSes this is known as the
     * 'superfloppy' (e.g., LS120/Zip) format.  As I don't know how to find out
     * for sure if this is a magneto-optical disk I introduce a -I (ignore)
     * switch.  -Joey
     */
    if ((statbuf.st_rdev & 0xff3f) == 0x0300 || /* hda, hdb */
        (statbuf.st_rdev & 0xff0f) == 0x0800 || /* sd */
        (statbuf.st_rdev & 0xff3f) == 0x0d00 || /* xd */
        (statbuf.st_rdev & 0xff3f) == 0x1600)   /* hdc, hdd */
    is_full_disk = 1;

  /* Halt on 'full' fixed disk devices, if -I is not given. */
  if (is_full_disk && !ignore_full_disk)
    die ("Will not try to make filesystem on full-disk device '%s' (use -I if wanted).");

  /* get true hardware sector size if possible */
  /* if can't, use the default value */
  if (ioctl (dev, BLKSSZGET, &hw_sector_size) < 0)
    hw_sector_size = DEFAULT_HW_SECTOR_SIZE;
  /* allow user to override */
  if (hw_sector_size_set)
    hw_sector_size = hw_sector_size_user;

  /* verify logical sector size is sane for the hardware sector size */
  if (sector_size_set)
    {
      if (sector_size < hw_sector_size)
        {
          fprintf (stderr,
                   "%s: Logical sector size (%d) cannot be less than hardware sector size (%d).\n",
                   program_name, sector_size, hw_sector_size);
          exit (1);
        }
    }
  else                          /* if user did not set logical sector size, default to hardware sector size */
    sector_size = hw_sector_size;


  establish_params (statbuf.st_rdev, statbuf.st_size);
  /* Establish the media parameters */


  setup_tables ();              /* Establish the file system tables */


  /* check for any template problems with regard to the filesystem parameters
     and set lesser_sector_size and template_sectors_can_copy */
  if (use_template)
    {
      if (sector_size != 512)
        {
          fprintf (stderr,"Warning: Most boot loaders (unpatched) will not work with logical sector sizes other than 512.\n");
        }

      lesser_sector_size = sector_size;
      if (template_sector_size != sector_size)
        {
          fprintf (stderr,
                   "Warning: Boot code template sector size (%d) does not match that of filesystem (%d).",
                   template_sector_size, sector_size);
          if (template_sector_size > sector_size)
            {
              fprintf (stderr," The excess sector data will not be copied.\n");
            }
          else
            {
              fprintf (stderr, "\n");
              lesser_sector_size = template_sector_size;
            }
        }

      if (template_fat_type == 32 && size_fat != 32)
        die ("Boot code template is for FAT32, but filesystem is FAT12/16.");
      if (template_fat_type != 32 && size_fat == 32)
        die ("Boot code template is for FAT12/16, but filesystem is FAT32.");

      /* set max number of sectors we can copy */
      /* this is the lesser of reserved_sectors, template_reserved_sectors and template_sectors */
      if (reserved_sectors > template_reserved_sectors)
        template_sectors_can_copy = template_reserved_sectors;
      else
        template_sectors_can_copy = reserved_sectors;
      /* it is OK for a template to claim more reserved sectors than it really has,
         the excess are implied to be full of zeros */
      if (template_sectors_can_copy > template_sectors)
        template_sectors_can_copy = template_sectors;
    }

  if (check)                    /* scan for any bad block locations and mark them */
    check_blocks ();

  if (listfile)                 /* lockout the bad blocks given by the user */
    get_list_blocks (listfile);

  write_tables ();              /* Write the file system tables away! */

  if (verbose)
    printf ("Filesystem created successfully.\n");

  exit (0);                     /* Terminate with no errors! */
}


/* That's All Folks */
/* End:             */
