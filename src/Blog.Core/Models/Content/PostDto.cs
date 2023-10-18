using Blog.Core.Domain.Content;
using System.ComponentModel.DataAnnotations.Schema;
using System.ComponentModel.DataAnnotations;
using AutoMapper;

namespace Blog.Core.Models.Content
{
	public class PostDto : PostInListDto
	{
		public Guid CategoryId { get; set; }

		public string? Content { get; set; }

		public Guid AuthorUserId { get; set; }

		public string? Source { get; set; }

		public string? Tags { get; set; }

		public string? SeoDescription { get; set; }

		public DateTime? DateModified { get; set; }
		public bool IsPaid { get; set; }
		public double RoyaltyAmount { get; set; }
		public PostStatus Status { get; set; }

		public class AutoMapperProfiles : Profile
		{
			public AutoMapperProfiles()
			{
				CreateMap<Post, PostDto>();
			}
		}
	}
}
