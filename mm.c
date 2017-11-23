/*
 * mm-naive.c - The least memory-efficient malloc package.
 * 
 * In this naive approach, a block is allocated by allocating a
 * new page as needed.  A block is pure payload. There are no headers or
 * footers.  Blocks are never coalesced or reused.
 *
 * The heap check and free check always succeeds, because the
 * allocator doesn't depend on any of the old data.
 *
 * NOTE TO STUDENTS: Replace this header comment with your own header
 * comment that gives a high level description of your solution.
 */
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>

#include "mm.h"
#include "memlib.h"

typedef struct {
 size_t size;
 size_t data;
} block_header;

/* always use 16-byte alignment */
#define ALIGNMENT 16

/* rounds up to the nearest multiple of ALIGNMENT */
#define ALIGN(size) (((size) + (ALIGNMENT-1)) & ~(ALIGNMENT-1))

/* rounds up to the nearest multiple of mem_pagesize() */
#define PAGE_ALIGN(size) (((size) + (mem_pagesize()-1)) & ~(mem_pagesize()-1))
#define BYT_TO_BLK(bytes) (bytes >> 1)
#define BLK_TO_BYT(blks) (blks << 1)
#define HDRP(bp) ((char *)(bp) - sizeof(block_header))
#define NEXT_BLKP(bp) ((char *)(bp) + GET_SIZE(HDRP(bp)))
#define GO_TO_FTR(bp) ( HDRP(HDRP(NEXT_BLKP(bp))) )
#define OVERHEAD (sizeof(block_header) * 2)
#define NEXT_BLKP(bp) ((char *)(bp) + GET_SIZE(HDRP(bp)))
#define FTRP(bp) ((char *)(bp)+GET_SIZE(HDRP(bp))-OVERHEAD)

#define GET(p) (*(size_t *)(p))
#define GET_DATA(bp) ((block_header*)bp)->data
#define PUT(p, val) (*(size_t *)(p) = (val))
#define PACK(size, alloc) ((size) | (alloc))
#define GET_ALLOC(p) (GET(p) & 0x1)
#define GET_SIZE(p) (GET(p) & ~0xF)

#define CHUNK_SIZE (1 << 14)
#define CHUNK_ALIGN(size) (((size)+(CHUNK_SIZE-1)) & ~(CHUNK_SIZE-1))
#define CHUNK_OVERHEAD (sizeof(block_header) * 3)
#define BLK_HDR_SZ (sizeof(block_header))

static void* extend(size_t new_size);
static int set_allocated(void *bp, size_t size);
static void* set_new_chunk(size_t new_size);

//PUT(p, PACK(48, 1));

/*
  TO DO
  1) extend
  2) set allocated
  3) basic mm_check
  4) basic can_free
  5) basic unmap
  6) 
*/

void *current_avail = NULL;
void* first_bp = NULL;
int current_avail_size = 0;
int debug_on = 1;
int extend_amt = 8;
char in = 0;

/* 
 * mm_init - initialize the malloc package.
 */
int mm_init(void)
{
  current_avail = NULL;
  current_avail_size = 0;
  // GET aligned initial size 
  size_t num_pages = 4;
  size_t chunk_bytes = CHUNK_ALIGN(mem_pagesize()*num_pages);
  block_header* chunk_prolog_hdr = mem_map(chunk_bytes);
  if(chunk_prolog_hdr == NULL)
    return -1;

  // Check results of mem_map
  if(mem_is_mapped((void*)chunk_prolog_hdr,chunk_bytes) == 0)
    if(debug_on) {printf("Failed to init enough bytes\n"); scanf("%c",&in);}
  if( mem_is_mapped((void*)chunk_prolog_hdr, chunk_bytes + 1) != 1)
    if(debug_on) {printf("mem_map mapped too many bytes\n"); scanf("%c",&in);}


  //Place chunk header and prolog block, pack size and alloc, embed data specific to each blockgit
  PUT((void*)chunk_prolog_hdr, PACK(2*BLK_HDR_SZ, 1));
  GET_DATA(chunk_prolog_hdr) = chunk_bytes;             // REPRESENTS SIZE OF CHUNK

  //Place end of chunk ftr
  block_header* end_of_chunk_ftr = ((void*)chunk_prolog_hdr + chunk_bytes - sizeof(block_header));
  PUT((void*)end_of_chunk_ftr, PACK(0, 1));
  GET_DATA(end_of_chunk_ftr) = 0;

  //Place prolog ftr, pack size and alloc
  block_header* prolog_ftr = ((void*)chunk_prolog_hdr + sizeof(block_header));
  PUT((void*)prolog_ftr, PACK(2*BLK_HDR_SZ, 1));
  GET_DATA(end_of_chunk_ftr) = 0;

  //Place first block header
  block_header* first_block = ((void*)chunk_prolog_hdr + (sizeof(block_header)*2));
  size_t size_first_block = chunk_bytes - CHUNK_OVERHEAD; 
  PUT((void*)first_block, PACK(size_first_block, 0));

  // Place first bp
  char* first_bp = HDRP(first_block);

  // Place first block footer
  block_header* first_block_footer = (block_header*)FTRP(first_bp);
  PUT((void*)first_block_footer, PACK(size_first_block, 0));

  current_avail = first_bp; 
  current_avail_size = size_first_block - OVERHEAD;
  return 0;
}


static void* set_new_chunk(size_t new_size){

  block_header* chunk_prolog_hdr = mem_map(new_size);
  if(chunk_prolog_hdr == NULL){
    if(debug_on) {printf("Failed to init enough bytes\n"); scanf("%c",&in);}
    return NULL;
  }

  // Check results of mem_map
  if(mem_is_mapped((void*)chunk_prolog_hdr, new_size) == 0)
    if(debug_on) {printf("Failed to init enough bytes\n"); scanf("%c",&in);}
  if( mem_is_mapped((void*)chunk_prolog_hdr, new_size + 1) != 1)
    if(debug_on) {printf("mem_map mapped too many bytes\n"); scanf("%c",&in);}


  //Place chunk header and prolog block, pack size and alloc, embed data specific to each blockgit
  PUT((void*)chunk_prolog_hdr, PACK(2*BLK_HDR_SZ, 1));
  GET_DATA(chunk_prolog_hdr) = new_size;             // REPRESENTS SIZE OF CHUNK

  //Place end of chunk ftr
  block_header* end_of_chunk_ftr = ((void*)chunk_prolog_hdr + new_size - sizeof(block_header));
  PUT((void*)end_of_chunk_ftr, PACK(0, 1));
  GET_DATA(end_of_chunk_ftr) = 0;

  //Place prolog ftr, pack size and alloc
  block_header* prolog_ftr = ((void*)chunk_prolog_hdr + sizeof(block_header));
  PUT((void*)prolog_ftr, PACK(2*BLK_HDR_SZ, 1));
  GET_DATA(end_of_chunk_ftr) = 0;

  //Place first block header
  block_header* first_block = ((void*)chunk_prolog_hdr + (sizeof(block_header)*2));
  size_t size_first_block = new_size - CHUNK_OVERHEAD; 
  PUT((void*)first_block, PACK(size_first_block, 0));

  // Place first bp
  void* bp = HDRP(first_block);

  // Place first block footer
  block_header* first_block_footer = (block_header*)FTRP(bp);
  PUT((void*)first_block_footer, PACK(size_first_block, 0));

  current_avail_size = size_first_block - OVERHEAD;
  return bp;
}

/* 
 * mm_malloc - Allocate a block by using bytes from current_avail,
 *     grabbing a new page if necessary.
 */
void *mm_malloc(size_t size) {
 int new_size = ALIGN(size + OVERHEAD);
 void *bp = first_bp;

 while (GET_SIZE(HDRP(bp)) != 0) {  // WHILE HAVE NOT REACHED END OF CHUNK
    if (!GET_ALLOC(HDRP(bp)) && (GET_SIZE(HDRP(bp)) >= new_size)) {  // IF UNALLOC AND SIZE IS LARGE ENOUGH
      set_allocated(bp, new_size);  // SET AS ALLOCATED AND RETURN bp
      return bp;
    }
    bp = NEXT_BLKP(bp);
 }
 
 if(extend(new_size) == NULL)
  return NULL;

 if(set_allocated(bp, new_size))
  if(debug_on) {printf("Failed to set new chunk\n"); scanf("%c",&in);}

 return bp;

}

static int set_allocated(void *bp, size_t size) {
 size_t extra_size = GET_SIZE(HDRP(bp)) - size;
 if (extra_size > ALIGN(1 + OVERHEAD)) {  // SPLIT BLOCK
    PUT((void*) HDRP(bp), PACK(size, 1)); // SET ALLOC HDR SIZE/ALLOC
    PUT((void*) FTRP(bp), PACK(size, 1)); // SET ALLOC FTR SIZE/ALLOC

    PUT((void*) HDRP(NEXT_BLKP(bp)), PACK(extra_size, 0)); // SET UNALLOC FTR SIZE/ALLOC
    PUT((void*) FTRP(NEXT_BLKP(bp)), PACK(extra_size, 0)); // SET UNALLOC FTR SIZE/ALLOC
 }else{ // NO NEED TO SPLIT BLOCK
    PUT((void*) HDRP(bp), PACK(size, 1)); // SET ALLOC HDR SIZE/ALLOC
    PUT((void*) FTRP(bp), PACK(size, 1)); // SET ALLOC FTR SIZE/ALLOC
 }

 return 0;

}

/*
 * EXTENDS available space by aqcuiring new chunk
 */
static void* extend(size_t new_size) {
 size_t chunk_size = CHUNK_ALIGN(new_size*extend_amt);
 void *bp = set_new_chunk(chunk_size);
 if(bp == NULL)
     if(debug_on) {printf("EXTEND failed to init new chunk\n"); scanf("%c",&in);}

  return bp;
}




/*
 * mm_free - Freeing a block does nothing.
 */
void mm_free(void *ptr)
{
  if(ptr == NULL)
  {  if(debug_on) {printf("mnm_free was passed null ptr\n"); scanf("%c",&in);}   return;    }
    
}

/*
 * mm_check - Check whether the heap is ok, so that mm_malloc()
 *            and proper mm_free() calls won't crash.
 */
int mm_check()
{
  return 1;
}

/*
 * mm_check - Check whether freeing the given `p`, which means that
 *            calling mm_free(p) leaves the heap in an ok state.
 * 1 = valid, 0 = invalid
 */
int mm_can_free(void *p)
{
  // check NULLn
  if(p == NULL) if(debug_on) {printf("mm_can_free passed null ptr\n"); scanf("%c",&in);} return 0;

  // CHECK IF NOT PAGE ALIGNED
  if((size_t)p % mem_pagesize() != 0) if(debug_on) {printf("ADDR given to mm_can_free not page aligned\n"); scanf("%c",&in); } return 0;

  // CHECK IS MAPPED
  size_t block_size = GET_SIZE(HDRP(p));
  if(mem_is_mapped(p, block_size) == 0) if(debug_on) {printf("mm_can detected attempted free of UNMAPPED MEM\n"); scanf("%c",&in);} return 0;

  return 1;


}
