using Blog.Core.Domain.Content;
using Blog.Core.Repositories;
using Blog.Data.SeedWorks;
using Microsoft.EntityFrameworkCore;

namespace Blog.Data.Repositories
{
	public class PostRepository : RepositoryBase<Post, Guid>, IPostRepository
	{
		public PostRepository(BlogContext context) : base(context)
		{

		}

		public Task<List<Post>> GetPopularPostsAsync(int count)
		{
			return _context.Posts.OrderByDescending(x => x.ViewCount).Take(count).ToListAsync();
		}
	}
}
